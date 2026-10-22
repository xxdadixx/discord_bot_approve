import io
import csv
import os
import time
import secrets
import aiosqlite
import discord
from discord import app_commands
from discord.ext import commands, tasks
from dotenv import load_dotenv

# --- CONFIGURATION ---
load_dotenv()

BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN")
GUILD_ID = int(os.getenv("GUILD_ID", 0))
MOD_CHANNEL_ID = int(os.getenv("MOD_CHANNEL_ID", 0))
VERIFIED_ROLE_ID = int(os.getenv("VERIFIED_ROLE_ID", 0))
AUDIT_LOG_CHANNEL_ID = int(os.getenv("AUDIT_LOG_CHANNEL_ID", 0))

# Dynamic database directory initialization with automatic directory creation
DATA_DIR = os.getenv("DATA_DIR", "/app/data" if os.path.exists("/app/data") else ".")
os.makedirs(DATA_DIR, exist_ok=True)
DB_FILE = os.path.join(DATA_DIR, "verifications.db")

TOKEN_EXPIRATION_HOURS = 24
EXPIRATION_SECONDS = TOKEN_EXPIRATION_HOURS * 3600

if not BOT_TOKEN or not GUILD_ID or not MOD_CHANNEL_ID or not VERIFIED_ROLE_ID:
    raise ValueError("Missing required configuration values in .env file.")


def generate_token() -> str:
    return f"VERIFY-{secrets.token_hex(4).upper()}"


# --- DATABASE HELPERS ---
async def init_db():
    """Initializes SQLite schema, concurrency PRAGMAs, performance indexes, and schema migrations."""
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute("PRAGMA journal_mode=WAL;")
        await db.execute("PRAGMA busy_timeout=5000;")

        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS verifications (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                evidence_text TEXT,
                evidence_url TEXT,
                status TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER
            )
        """
        )

        # Non-destructive migration for existing database files
        try:
            await db.execute("ALTER TABLE verifications ADD COLUMN updated_at INTEGER;")
        except Exception:
            pass  # Column already exists

        await db.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_verifications_user_status 
            ON verifications (user_id, status)
        """
        )
        await db.commit()


async def has_active_pending_verification(user_id: int) -> bool:
    """
    Checks whether a user currently has an unexpired 'PENDING' verification token.
    Enforces inline temporal expiration to prevent stale lockouts.
    """
    cutoff = int(time.time()) - EXPIRATION_SECONDS
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute(
            "SELECT 1 FROM verifications WHERE user_id = ? AND status = 'PENDING' AND created_at >= ? LIMIT 1",
            (user_id, cutoff),
        ) as cursor:
            return (await cursor.fetchone()) is not None


async def get_all_pending_verifications() -> list[dict]:
    """Fetches all currently pending verification requests in FIFO order."""
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute(
            "SELECT token, user_id, evidence_text, evidence_url, created_at FROM verifications WHERE status = 'PENDING' ORDER BY created_at ASC"
        ) as cursor:
            rows = await cursor.fetchall()
            return [
                {
                    "token": row[0],
                    "user_id": row[1],
                    "evidence_text": row[2],
                    "evidence_url": row[3],
                    "created_at": row[4],
                }
                for row in rows
            ]


async def try_claim_and_update_status(token: str, new_status: str) -> bool:
    """
    Atomically updates a verification token status and updated_at timestamp ONLY if currently 'PENDING'.
    Returns True if the record was successfully claimed and updated, False otherwise.
    """
    now = int(time.time())
    async with aiosqlite.connect(DB_FILE) as db:
        cursor = await db.execute(
            "UPDATE verifications SET status = ?, updated_at = ? WHERE token = ? AND status = 'PENDING'",
            (new_status, now, token),
        )
        await db.commit()
        return cursor.rowcount > 0


async def get_verification(token: str) -> dict | None:
    """
    Fetches submission data and dynamically calculates expiration state.
    Pure query function with zero side-effects.
    """
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute(
            "SELECT user_id, evidence_text, evidence_url, status, created_at FROM verifications WHERE token = ?",
            (token,),
        ) as cursor:
            row = await cursor.fetchone()
            if not row:
                return None

            user_id, evidence_text, evidence_url, status, created_at = row
            current_time = int(time.time())

            # Evaluate expiration dynamically for the caller
            if status == "PENDING" and (current_time - created_at) > EXPIRATION_SECONDS:
                status = "EXPIRED"

            return {
                "user_id": user_id,
                "evidence_text": evidence_text,
                "evidence_url": evidence_url,
                "status": status,
                "created_at": created_at,
            }


async def get_verification_stats() -> dict:
    """
    Executes a single-pass SQL aggregation to fetch queue metrics and average review latency.
    """
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute(
            """
            SELECT
                COUNT(CASE WHEN status = 'APPROVED' THEN 1 END) as approved_count,
                COUNT(CASE WHEN status = 'REJECTED' THEN 1 END) as rejected_count,
                COUNT(CASE WHEN status = 'PENDING' THEN 1 END) as pending_count,
                COUNT(CASE WHEN status = 'EXPIRED' THEN 1 END) as expired_count,
                AVG(CASE WHEN status IN ('APPROVED', 'REJECTED') AND updated_at IS NOT NULL THEN (updated_at - created_at) END) as avg_response_seconds
            FROM verifications
        """
        ) as cursor:
            row = await cursor.fetchone()
            return {
                "approved": row[0] or 0,
                "rejected": row[1] or 0,
                "pending": row[2] or 0,
                "expired": row[3] or 0,
                "avg_response_seconds": row[4],
            }


async def update_status(token: str, status: str):
    """Updates the status of a verification request."""
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute(
            "UPDATE verifications SET status = ? WHERE token = ?", (status, token)
        )
        await db.commit()


async def get_latest_user_verification(user_id: int) -> tuple[str, dict] | None:
    """Fetches the most recent verification submission for a user."""
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute(
            "SELECT token FROM verifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 1",
            (user_id,),
        ) as cursor:
            row = await cursor.fetchone()
            if row:
                token = row[0]
                record = await get_verification(token)
                return token, record
    return None


def sanitize_csv_cell(value: str | None) -> str | None:
    """
    Sanitizes cell inputs against CSV Formula Injection (CWE-1236).
    Prepends a single quote if the text begins with trigger characters.
    """
    if not value or not isinstance(value, str):
        return value
    if value.startswith(("=", "+", "-", "@", "\t", "\r")):
        return f"'{value}"
    return value


async def export_verifications_to_csv_buffer() -> io.BytesIO:
    """
    Fetches all historical verification records and exports them into an in-memory CSV BytesIO buffer.
    Applies formula injection sanitization to user-supplied text fields.
    """
    async with aiosqlite.connect(DB_FILE) as db:
        async with db.execute(
            """
            SELECT token, user_id, status, evidence_text, evidence_url, created_at, updated_at 
            FROM verifications 
            ORDER BY created_at DESC
        """
        ) as cursor:
            rows = await cursor.fetchall()

    string_buffer = io.StringIO()
    writer = csv.writer(string_buffer)

    # Write CSV Header Row
    writer.writerow(
        [
            "Token",
            "User ID",
            "Status",
            "Evidence Text",
            "Evidence URL",
            "Created At (UTC Epoch)",
            "Updated At (UTC Epoch)",
        ]
    )

    for row in rows:
        token, user_id, status, evidence_text, evidence_url, created_at, updated_at = (
            row
        )
        writer.writerow(
            [
                token,
                user_id,
                status,
                sanitize_csv_cell(evidence_text),
                sanitize_csv_cell(evidence_url),
                created_at,
                updated_at,
            ]
        )

    bytes_buffer = io.BytesIO(string_buffer.getvalue().encode("utf-8"))
    bytes_buffer.seek(0)
    return bytes_buffer


# --- MODALS & VIEWS ---
class PendingPaginationView(discord.ui.View):
    def __init__(self, records: list[dict], author_id: int, items_per_page: int = 5):
        super().__init__(timeout=180)
        self.records = records
        self.author_id = author_id
        self.items_per_page = items_per_page
        self.current_page = 0
        self.total_pages = max(1, (len(records) + items_per_page - 1) // items_per_page)
        self.update_button_states()

    def update_button_states(self):
        """Disables navigation buttons when at bounds."""
        self.prev_btn.disabled = self.current_page == 0
        self.next_btn.disabled = self.current_page >= self.total_pages - 1

    def create_embed(self) -> discord.Embed:
        """Constructs the Embed for the current page slice."""
        embed = discord.Embed(
            title=f"Pending Verification Queue ({len(self.records)} Total)",
            color=discord.Color.gold(),
        )

        start_idx = self.current_page * self.items_per_page
        page_items = self.records[start_idx : start_idx + self.items_per_page]

        for item in page_items:
            details_text = item["evidence_text"] or "*Attachment only*"
            if len(details_text) > 100:
                details_text = details_text[:97] + "..."

            embed.add_field(
                name=f"Token: `{item['token']}` | User: <@{item['user_id']}>",
                value=f"Submitted: <t:{item['created_at']}:R>\nDetails: {details_text}",
                inline=False,
            )

        embed.set_footer(text=f"Page {self.current_page + 1} of {self.total_pages}")
        return embed

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.author_id:
            await interaction.response.send_message(
                "You are not authorized to control this pagination view.",
                ephemeral=True,
            )
            return False
        return True

    @discord.ui.button(label="◀ Previous", style=discord.ButtonStyle.secondary)
    async def prev_btn(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ):
        self.current_page -= 1
        self.update_button_states()
        await interaction.response.edit_message(embed=self.create_embed(), view=self)

    @discord.ui.button(label="Next ▶", style=discord.ButtonStyle.secondary)
    async def next_btn(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ):
        self.current_page += 1
        self.update_button_states()
        await interaction.response.edit_message(embed=self.create_embed(), view=self)


class RejectModal(discord.ui.Modal, title="Reject Verification"):
    reason = discord.ui.TextInput(
        label="Reason for Rejection",
        style=discord.TextStyle.paragraph,
        placeholder="Explain why this verification evidence is invalid or incomplete...",
        required=True,
        max_length=500,
    )

    def __init__(self, token: str):
        super().__init__()
        self.token = token

    async def on_submit(self, interaction: discord.Interaction):
        await process_rejection(interaction, self.token, self.reason.value)


class ReviewView(discord.ui.View):
    def __init__(self, token: str):
        super().__init__(timeout=None)
        self.token = token

        self.approve_btn.custom_id = f"review:approve:{token}"
        self.reject_btn.custom_id = f"review:reject:{token}"

    @discord.ui.button(label="Approve", style=discord.ButtonStyle.success)
    async def approve_btn(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ):
        await process_approval(interaction, self.token)

    @discord.ui.button(label="Reject", style=discord.ButtonStyle.danger)
    async def reject_btn(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ):
        await interaction.response.send_modal(RejectModal(self.token))


# --- BOT CLIENT ---
class BotClient(commands.Bot):
    def __init__(self):
        intents = discord.Intents.default()
        intents.members = True
        super().__init__(command_prefix="!", intents=intents)

    async def setup_hook(self):
        await init_db()

        # Re-register views for active pending verifications
        async with aiosqlite.connect(DB_FILE) as db:
            async with db.execute(
                "SELECT token FROM verifications WHERE status = 'PENDING'"
            ) as cursor:
                async for row in cursor:
                    self.add_view(ReviewView(row[0]))

        guild = discord.Object(id=GUILD_ID)
        self.tree.copy_global_to(guild=guild)
        await self.tree.sync(guild=guild)

        if not check_expired_tokens.is_running():
            check_expired_tokens.start()


bot = BotClient()


# --- AUDIT LOG HELPER ---
async def log_audit_action(guild: discord.Guild, embed: discord.Embed):
    """Sends formatted log embeds to the designated audit log channel."""
    if not AUDIT_LOG_CHANNEL_ID:
        return

    audit_channel = guild.get_channel(AUDIT_LOG_CHANNEL_ID)
    if not audit_channel:
        try:
            audit_channel = await guild.fetch_channel(AUDIT_LOG_CHANNEL_ID)
        except (discord.NotFound, discord.Forbidden):
            return

    if audit_channel:
        await audit_channel.send(embed=embed)


# --- BACKGROUND EXPIRATION TASK ---
@tasks.loop(hours=1)
async def check_expired_tokens():
    """Background job that flags expired tokens in SQLite."""
    cutoff = int(time.time()) - EXPIRATION_SECONDS
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute(
            "UPDATE verifications SET status = 'EXPIRED' WHERE status = 'PENDING' AND created_at < ?",
            (cutoff,),
        )
        await db.commit()


# --- PROCESS HANDLERS ---
async def fetch_member_safe(
    guild: discord.Guild, user_id: int
) -> discord.Member | None:
    """Safely retrieves a member from cache or fetches from API."""
    member = guild.get_member(user_id)
    if not member:
        try:
            member = await guild.fetch_member(user_id)
        except discord.NotFound:
            return None
    return member


async def process_approval(interaction: discord.Interaction, token: str):
    if not interaction.user.guild_permissions.manage_roles:
        await interaction.response.send_message(
            "You lack permission to approve requests.", ephemeral=True
        )
        return

    record = await get_verification(token)
    if not record:
        await interaction.response.send_message(
            "Verification token not found.", ephemeral=True
        )
        return

    if record["status"] == "EXPIRED":
        await interaction.response.send_message(
            f"Token `{token}` has expired.", ephemeral=True
        )
        return

    # Attempt atomic state transition
    success = await try_claim_and_update_status(token, "APPROVED")
    if not success:
        await interaction.response.send_message(
            f"Token `{token}` has already been processed or is no longer pending.",
            ephemeral=True,
        )
        return

    guild = interaction.guild
    role = guild.get_role(VERIFIED_ROLE_ID)
    member = await fetch_member_safe(guild, record["user_id"])

    if not member or not role:
        await interaction.response.send_message(
            "Target member or configured role could not be resolved.", ephemeral=True
        )
        return

    await member.add_roles(
        role, reason=f"Approved via token {token} by {interaction.user}"
    )

    embed = interaction.message.embeds[0]
    embed.color = discord.Color.green()
    embed.set_footer(
        text=f"Approved by {interaction.user.display_name} | Token: {token}"
    )

    await interaction.response.edit_message(embed=embed, view=None)

    try:
        await member.send(
            f"Your verification submission has been approved! You have been granted the **{role.name}** role."
        )
    except discord.Forbidden:
        pass

    audit_embed = discord.Embed(
        title="Verification Approved",
        color=discord.Color.green(),
        timestamp=interaction.created_at,
    )
    audit_embed.add_field(
        name="Target User", value=f"{member.mention} (`{member.id}`)", inline=True
    )
    audit_embed.add_field(
        name="Moderator",
        value=f"{interaction.user.mention} (`{interaction.user.id}`)",
        inline=True,
    )
    audit_embed.add_field(name="Token", value=f"`{token}`", inline=True)
    audit_embed.add_field(
        name="Role Granted", value=f"<@&{VERIFIED_ROLE_ID}>", inline=False
    )

    await log_audit_action(guild, audit_embed)


async def process_rejection(
    interaction: discord.Interaction, token: str, reason: str = "No reason provided."
):
    if not interaction.user.guild_permissions.manage_roles:
        await interaction.response.send_message(
            "You lack permission to reject requests.", ephemeral=True
        )
        return

    record = await get_verification(token)
    if not record or record["status"] != "PENDING":
        await interaction.response.send_message(
            f"Token `{token}` is invalid or already processed.", ephemeral=True
        )
        return

    # Attempt atomic state transition
    success = await try_claim_and_update_status(token, "REJECTED")
    if not success:
        await interaction.response.send_message(
            f"Token `{token}` has already been processed or is no longer pending.",
            ephemeral=True,
        )
        return

    embed = interaction.message.embeds[0]
    embed.color = discord.Color.red()
    embed.add_field(name="Rejection Reason", value=reason, inline=False)
    embed.set_footer(
        text=f"Rejected by {interaction.user.display_name} | Token: {token}"
    )

    await interaction.response.edit_message(embed=embed, view=None)

    guild = interaction.guild
    member = await fetch_member_safe(guild, record["user_id"])
    if member:
        try:
            await member.send(
                f"Your verification submission (`{token}`) was rejected.\n**Reason:** {reason}"
            )
        except discord.Forbidden:
            pass

    audit_embed = discord.Embed(
        title="Verification Rejected",
        color=discord.Color.red(),
        timestamp=interaction.created_at,
    )
    audit_embed.add_field(
        name="Target User",
        value=f"<@{record['user_id']}> (`{record['user_id']}`)",
        inline=True,
    )
    audit_embed.add_field(
        name="Moderator",
        value=f"{interaction.user.mention} (`{interaction.user.id}`)",
        inline=True,
    )
    audit_embed.add_field(name="Token", value=f"`{token}`", inline=True)
    audit_embed.add_field(name="Reason", value=reason, inline=False)

    await log_audit_action(guild, audit_embed)


# --- ERROR HANDLING ---
@bot.tree.error
async def on_app_command_error(
    interaction: discord.Interaction, error: app_commands.AppCommandError
):
    if isinstance(error, app_commands.CommandOnCooldown):
        minutes, seconds = divmod(int(error.retry_after), 60)
        time_str = f"{minutes}m {seconds}s" if minutes > 0 else f"{seconds}s"
        await interaction.response.send_message(
            f"⌛ You are submitting evidence too frequently! Please wait **{time_str}** before submitting again.",
            ephemeral=True,
        )
    elif isinstance(error, app_commands.MissingPermissions):
        await interaction.response.send_message(
            "You do not have permission to run this command.", ephemeral=True
        )
    else:
        print(f"Command Error: {error}")


# --- COMMANDS ---
@bot.tree.command(
    name="submit", description="Submit text or image evidence for verification review."
)
@app_commands.checks.cooldown(1, 300.0, key=lambda i: (i.guild_id, i.user.id))
@app_commands.describe(
    details="Optional text details or links for verification",
    image="Optional image file attachment (PNG, JPG, WebP)",
)
async def submit(
    interaction: discord.Interaction,
    details: str = None,
    image: discord.Attachment = None,
):
    if not details and not image:
        await interaction.response.send_message(
            "Please provide either text details or an image file as evidence.",
            ephemeral=True,
        )
        return

    if image and (
        not image.content_type or not image.content_type.startswith("image/")
    ):
        await interaction.response.send_message(
            "The attached file must be an image format (PNG, JPG, WebP, GIF).",
            ephemeral=True,
        )
        return

    mod_channel = interaction.guild.get_channel(MOD_CHANNEL_ID)
    if not mod_channel:
        await interaction.response.send_message(
            "Review channel configuration error. Please contact an administrator.",
            ephemeral=True,
        )
        return

    if await has_active_pending_verification(interaction.user.id):
        await interaction.response.send_message(
            "⚠️ You already have an active verification request pending review. Please wait for moderators to review your submission before submitting a new one.",
            ephemeral=True,
        )
        return

    token = generate_token()
    image_url = image.url if image else None
    created_at = int(time.time())

    # Pre-build View & Embed prior to database commit
    view = ReviewView(token)
    review_embed = discord.Embed(
        title="New Verification Request",
        color=discord.Color.gold(),
        timestamp=interaction.created_at,
    )
    review_embed.add_field(
        name="User",
        value=f"{interaction.user.mention} (`{interaction.user.id}`)",
        inline=False,
    )
    review_embed.add_field(name="Verification Token", value=f"`{token}`", inline=False)

    if details:
        review_embed.add_field(name="Submitted Text", value=details, inline=False)

    if image_url:
        review_embed.set_image(url=image_url)

    review_embed.set_thumbnail(url=interaction.user.display_avatar.url)

    # Execute DB Insert
    async with aiosqlite.connect(DB_FILE) as db:
        await db.execute(
            "INSERT INTO verifications (token, user_id, evidence_text, evidence_url, status, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (token, interaction.user.id, details, image_url, "PENDING", created_at),
        )
        await db.commit()

    # Attempt Channel Dispatch with Rollback Safeguard
    try:
        bot.add_view(view)
        await mod_channel.send(embed=review_embed, view=view)
    except Exception as e:
        # Roll back database insertion if message dispatch fails
        async with aiosqlite.connect(DB_FILE) as db:
            await db.execute("DELETE FROM verifications WHERE token = ?", (token,))
            await db.commit()

        print(f"Failed to send verification request to mod channel: {e}")
        await interaction.response.send_message(
            "An error occurred while submitting your request to the review channel. Please try again later.",
            ephemeral=True,
        )
        return

    await interaction.response.send_message(
        f"Your evidence has been submitted successfully! Your reference token is `{token}`. (Expires in {TOKEN_EXPIRATION_HOURS} hours)",
        ephemeral=True,
    )


@bot.tree.command(
    name="approve", description="Manual token approval command for reviewers."
)
@app_commands.checks.has_permissions(manage_roles=True)
@app_commands.describe(token="The verification token to approve")
async def approve(interaction: discord.Interaction, token: str):
    token = token.upper().strip()
    await process_approval(interaction, token)


def format_duration(seconds: float | None) -> str:
    """Converts raw seconds into a human-readable duration string."""
    if seconds is None or seconds <= 0:
        return "N/A"
    total_seconds = int(seconds)
    hours, remainder = divmod(total_seconds, 3600)
    minutes, secs = divmod(remainder, 60)

    if hours > 0:
        return f"{hours}h {minutes}m"
    if minutes > 0:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


@bot.tree.command(
    name="stats",
    description="Display overall queue metrics or export historical CSV data.",
)
@app_commands.checks.has_permissions(manage_roles=True)
@app_commands.describe(
    export="Set to True to download a CSV file containing all historical verification data."
)
async def stats(interaction: discord.Interaction, export: bool = False):
    if export:
        await interaction.response.defer(ephemeral=True)

        bytes_buffer = await export_verifications_to_csv_buffer()
        filename = f"verifications_export_{int(time.time())}.csv"
        discord_file = discord.File(fp=bytes_buffer, filename=filename)

        await interaction.followup.send(
            content="📊 Here is the complete historical verification data export:",
            file=discord_file,
            ephemeral=True,
        )
        return

    data = await get_verification_stats()

    total_processed = data["approved"] + data["rejected"]
    approval_rate = (
        f"{(data['approved'] / total_processed * 100):.1f}%"
        if total_processed > 0
        else "N/A"
    )
    avg_latency = format_duration(data["avg_response_seconds"])

    embed = discord.Embed(
        title="Verification System Metrics",
        color=discord.Color.blue(),
        timestamp=interaction.created_at,
    )
    embed.add_field(name="Approved", value=f"**{data['approved']}**", inline=True)
    embed.add_field(name="Rejected", value=f"**{data['rejected']}**", inline=True)
    embed.add_field(name="Pending Review", value=f"**{data['pending']}**", inline=True)
    embed.add_field(name="Expired", value=f"**{data['expired']}**", inline=True)
    embed.add_field(name="Approval Rate", value=f"**{approval_rate}**", inline=True)
    embed.add_field(name="Avg Response Time", value=f"**{avg_latency}**", inline=True)

    await interaction.response.send_message(embed=embed, ephemeral=True)


@bot.tree.command(
    name="pending",
    description="List all currently pending verification requests (Admin only).",
)
@app_commands.checks.has_permissions(manage_roles=True)
async def pending(interaction: discord.Interaction):
    records = await get_all_pending_verifications()

    if not records:
        await interaction.response.send_message(
            "There are currently no pending verification requests in the queue.",
            ephemeral=True,
        )
        return

    view = PendingPaginationView(records=records, author_id=interaction.user.id)
    embed = view.create_embed()
    await interaction.response.send_message(embed=embed, view=view, ephemeral=True)


@bot.event
async def on_ready():
    print(f"Bot online as {bot.user} (ID: {bot.user.id})")


if __name__ == "__main__":
    bot.run(BOT_TOKEN)
