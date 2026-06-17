# UPI Autopay Bot — Open Marketplace Version

This version runs the Telegram bot and the web admin panel in one Python process.

This build supports MongoDB-backed live storage for deployment without a persistent disk volume. SQLite remains available for local testing.

## Main flow

Pairing has been removed.

1. A registered sender sends a QR photo.
2. The bot validates and rebuilds the QR as a clean generated QR.
3. The bot creates an open marketplace offer.
4. All online receivers get an **Accept Scan** button.
5. The first receiver to accept gets the QR in the same message where they tapped **Accept Scan**.
6. Later receivers see that the offer expired/was already claimed.
7. Every QR expires after the admin-set QR expire time, whether it is accepted or not. If it expires while pending, the sender reserve is released.

The QR image is shown only to the winning receiver after they successfully claim the offer.

## User bot commands

The Telegram bot is user-only. Admin controls live in the web panel.

### Sender commands

```text
/start
/myid
/status
/wallet
/loadwallet
/history
/stats
/dispute
```

### Receiver commands

```text
/start
/myid
/on LIMIT
/off
/pending
/done (reply to a QR or tap the button)
/failed (reply to a QR or tap the button)
/earnings
/withdraw
/history
/stats
/dispute
```

Receivers are automatically set offline when their remaining limit reaches zero.

## Web admin panel

Open:

```text
http://127.0.0.1:8080/admin
```

Admin features:

- Users: add/disable senders and receivers.
- Dashboard: maintenance mode toggle plus live stats for pending QR, disputes, payouts, payment reviews, sender balances, and receiver payable totals.
- Marketplace: sender/receiver rates and receiver online/offline toggles.
- Wallets: view sender balances and receiver due amounts, plus manual adjustments.
- Payments: BEP20/Polygon wallet addresses, Binance Pay ID/name, manual TxHash tolerances, minimum wallet top-up, and deposit review.
- Payout Requests: review receiver withdrawal requests with red sidebar count. Receiver withdrawals are blocked until available balance reaches the admin-set minimum payout amount.
- Disputes: review `/dispute` submissions with clear statuses: Open, Under Review, Resolved, and Rejected. The dispute list now stays compact with a Reply/View Chat button, new-reply badges, popup chat history, and admin replies/resolution messages from the popup.
- Pending QR: view open/claimed QR offers and statuses. Clicking a QR ID opens its admin detail page with QR image, users, rates, timestamps, linked disputes, and admin status override.
- QR status override: admin can change any order to Done or Failed; both sender and receiver are notified, receiver earnings are deducted when a completed order is reversed, and the sender charge is added back/released automatically.
- Stats: marketplace statistics.
- Broadcast: send web-panel broadcasts to users by language and target group, including a dedicated Admins target.
- Secret Settings: web login credentials, payment verification API keys/secrets, QR expire time, bot timing, and receiver withdrawal minimum payout.

## Maintenance mode

Maintenance is controlled from the Dashboard. When it is ON, normal users are blocked from bot actions and see a maintenance message. Owner/admin Telegram IDs from `ADMIN_IDS` can still test the bot, and senders can still use `/wallet` and `/loadwallet` for wallet access. Receiver online/offline notifications are not sent to senders while maintenance is ON.

## Payment behavior

The wallet system uses an internal ledger.

Sender load flow:

1. Sender runs `/loadwallet` and chooses a top-up method.
2. The bot creates a unique USDT amount with decimals.
3. Auto verification scans for exact incoming payments.
4. Sender can use the Manual Verify button on the payment message if automatic checking does not verify it.
5. Tx hashes / Binance transaction IDs are stored so the same payment cannot be credited twice.
6. Admin can manually verify, approve, or reject from the Payments page.

QR charging flow:

- On QR offer creation, the sender rate is reserved from the sender wallet.
- If the offer expires or the receiver marks Failed, the reserve is released.
- If the receiver marks Done, the sender is charged and the receiver earning is added.
- If admin changes a completed order back to Failed, that order's receiver earning is deducted, the sender charge is added back to the sender wallet, and both parties get a Telegram notification.

## Required environment variables

```env
BOT_TOKEN=your_bot_token
ADMIN_IDS=your_telegram_numeric_chat_id
BOT_ADMIN_CONTACTS=@youradmin
ADMIN_PANEL_USERNAME=admin
ADMIN_PANEL_PASSWORD=make-a-strong-password
ADMIN_SESSION_SECRET=make-a-long-random-secret
BOT_TZ=Asia/Kolkata
STORAGE_BACKEND=mongodb
MONGO_URI=mongodb+srv://username:password@cluster.mongodb.net/?retryWrites=true&w=majority
MONGO_DB_NAME=upi_autopay_bot
DB_PATH=/tmp/upi_autopay_bot.db
MODE=polling
PORT=8080
```

## Marketplace/payment variables

Wallet addresses, Binance Pay ID/name, tolerances, and minimum top-up are saved from the Payments page. Verification API keys and confirmations are saved from Secret Settings.

```env
QR_EXPIRE_MINUTES=5
DEFAULT_SENDER_RATE_USDT=0
DEFAULT_RECEIVER_RATE_USDT=0
DEFAULT_MIN_PAYOUT_USDT=1
DEFAULT_MIN_WALLET_TOPUP_USDT=1
BEP20_MANUAL_TOLERANCE_USDT=0.01
POLYGON_MANUAL_TOLERANCE_USDT=0.07

BEP20_WALLET_ADDRESS=
POLYGON_WALLET_ADDRESS=
BINANCE_PAY_ID=
BINANCE_PAY_NAME=

BSCSCAN_API_KEY=
POLYGONSCAN_API_KEY=
BEP20_REQUIRED_CONFIRMATIONS=3
POLYGON_REQUIRED_CONFIRMATIONS=20

BINANCE_API_KEY=
BINANCE_API_SECRET=
BINANCE_API_BASE_URL=https://api.binance.com
BINANCE_PAY_HISTORY_LOOKBACK_SECONDS=3600
BINANCE_RECV_WINDOW_MS=5000
```

## MongoDB live deployment

This build is MongoDB-ready for live deployment. Set `MONGO_URI` and the bot will restore/sync its database snapshot through MongoDB automatically. You do **not** need a Railway Volume or any persistent disk.

Recommended production variables:

```env
STORAGE_BACKEND=mongodb
MONGO_URI=mongodb+srv://username:password@cluster.mongodb.net/?retryWrites=true&w=majority
MONGO_DB_NAME=upi_autopay_bot
MONGO_STATE_COLLECTION=bot_state
MONGO_SNAPSHOT_ID=upi_autopay_main
MONGO_SYNC_ON_COMMIT=true
DB_PATH=/tmp/upi_autopay_bot.db
MODE=polling
PORT=8080
ADMIN_COOKIE_SECURE=true
```

How it works:

- MongoDB is the persistent live store.
- The bot restores a temporary local runtime database from MongoDB on startup.
- After commits, the bot syncs the latest database snapshot back to MongoDB.
- This keeps all existing bot/admin behavior intact while removing the need for local persistent storage.

For local-only testing without MongoDB, use:

```env
STORAGE_BACKEND=sqlite
DB_PATH=upi_autopay_bot.db
```

If you already have an existing local `upi_autopay_bot.db` and want to move it to MongoDB, place it beside `bot.py`, set `STORAGE_BACKEND=mongodb` and `MONGO_URI`, then start the bot once. If MongoDB has no saved snapshot yet, the bot will create the MongoDB snapshot from that local database.

## Railway deployment

Set the MongoDB variables above in Railway. Do not add a Railway Volume unless you intentionally want local SQLite mode.

## Important

Do not run two bot instances with the same token. Only one local/Railway/server process should be active at a time.

## Payment review UI fix

- Pending Payments proof popup now uses the same left-details / right-screenshot modal style as the reference project.
- USDT transaction hashes are shown as bold blue explorer links for BEP20/Polygon.
- Manual TxHash errors are now displayed as specific review reasons instead of raw provider text such as `NOTOK`.
- The proof screenshot can be opened fullscreen and closed from the top-right cross.

## Payment review/manual verification fixes

- Manual Verify now stays locked once a payment session has already been submitted, processed, rejected, credited, or expired.
- Admin Approve/Reject actions now open confirmation popups before changing a payment review.
- Admin approval sends the sender the standard wallet top-up completed message with credited amount and current balance.
- Admin rejection sends the sender the standard payment-not-verified support message.

## Payment proof / TxHash validation cleanup

- The Pending Payments proof popup no longer shows the redundant `Status: Pending` row.
- Manual USDT TxHash checks now detect when a submitted TxHash belongs to a USDT transfer that was not sent to the configured payment wallet.
- Clear user-fixable TxHash problems, such as wrong wallet, wrong network/not found, duplicate hash, invalid hash, wrong token, or old transaction, are returned to the sender immediately with a simple user-facing message: “The transaction hash you submitted is incorrect. Please send the correct USDT transaction hash / TxID for this wallet top-up.” Specific technical reasons remain visible to admin/review logs only.

## Payment verification timeout

Manual TxHash checks are protected by `PAYMENT_VERIFY_TASK_TIMEOUT_SECONDS` so the bot never gets stuck after showing a checking message. If the chain API does not respond in time, the user is moved to screenshot proof/admin review instead of being left waiting.

The automatic payment watcher now checks newest active deposits first, runs a small concurrent batch, and uses public BEP20/Polygon RPC log scanning as a fallback when BscScan/PolygonScan is delayed, missing an API key, or rate-limited. Optional environment/admin settings: `PAYMENT_WATCH_BATCH_SIZE`, `PAYMENT_WATCH_CONCURRENCY`, `PAYMENT_AUTO_VERIFY_TIMEOUT_SECONDS`, `BEP20_RPC_URL`, `POLYGON_RPC_URL`, `BEP20_RPC_URLS`, `POLYGON_RPC_URLS`, `BEP20_RPC_BLOCK_CHUNK_SIZE`, `POLYGON_RPC_BLOCK_CHUNK_SIZE`, and `EVM_LOG_LOOKBACK_BLOCKS`.

## Admin pending QR expiry / wallet display fixes

- The Pending QRs page now includes an **Expire** action for every pending QR. Admin expiry works for both open offers and already-claimed pending QRs, marks the QR expired/failed, removes receiver action buttons where possible, and releases the sender reserve through the normal failed/expired settlement path.
- Wallet top-up completed confirmations now show the credited amount with 2 decimals, for example `$1.00 USDT`, instead of 4 decimals.

## Admin QR status override

- The QR detail page now includes **Change order status** for every order.
- Admin can switch an order to **Done** or **Failed** even after it was already completed/failed.
- When a completed order is changed to Failed, the receiver earning for that order is deducted and the sender charge is added back to the sender wallet.
- When a failed order is changed to Done, the sender is charged again and the receiver earning is credited again.
- Sender and receiver both receive Telegram notifications for the admin status change.

## Language support

The user-facing bot now supports English, Indonesian, Vietnamese, Chinese, and Spanish.

- Default language is English.
- On a user's first `/start`, the bot asks the user to choose a language.
- On later `/start` commands, the bot opens the normal start menu.
- Users can change language anytime with `/language` or the Language button in the start menu.
- The admin panel remains English.
- Admin-written content such as dispute replies and broadcast messages is not auto-translated.

## Language-targeted broadcasts

The admin Preset Messages page includes a **Broadcast by language** box. Choose the language and target role, then write the exact message to send. A Chinese broadcast is delivered only to Chinese-language users; English, Indonesian, Vietnamese, and Spanish work the same way. Users who never selected a language are treated as English.

### Admin Broadcast Panel

The admin sidebar includes a dedicated **📣 Broadcast** panel. Use it to send an admin-written message to all active users, senders, receivers, or admins, filtered by selected bot language: English, Indonesian, Vietnamese, Chinese, or Spanish. Users without a saved language are treated as English. Broadcast text is sent exactly as typed and is not auto-translated. Configured `ADMIN_IDS` are not excluded from broadcasts or marketplace delivery; sender/receiver broadcast targets include matching users plus configured admin IDs, and the Admins target sends only to configured admin IDs that have started the bot.


## Admin Telegram IDs in bot commands

Configured `ADMIN_IDS` are treated as virtual admins in the Telegram bot. They can use sender-side and receiver-side commands without being blocked by sender/receiver role checks. Admin IDs are not excluded from broadcasts, marketplace preset messages, receiver online notifications, or QR offers. To receive QR offers, an admin still needs to use `/on LIMIT`, the same as a receiver, so the marketplace capacity stays controlled.


### Sender cancel button

Senders now see a cancel button under each open QR offer. The button can cancel the order only after 2 minutes if no receiver has accepted it yet. Canceling releases the sender reserved balance and removes receiver accept buttons for that offer.
