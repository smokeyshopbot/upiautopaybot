import os
import tempfile

import bot


def main() -> None:
    bot.MONGO_ENABLED = False
    bot.DB_PATH = os.path.join(tempfile.gettempdir(), "upi_maintenance_test.db")
    if os.path.exists(bot.DB_PATH):
        os.remove(bot.DB_PATH)
    try:
        bot.init_db()
        bot.PAYMENT_VERIFICATION_LOG_MAX_ROWS = 1000
        bot.DB_STARTUP_VACUUM_MIN_MB = 1
        old = (bot.now_dt() - bot.timedelta(days=30)).isoformat(timespec="seconds")
        payload = "x" * 5000
        conn = bot.get_conn()
        with conn:
            conn.executemany(
                """
                INSERT INTO payment_verification_logs(ref_id, result, reason, raw_json, created_at)
                VALUES (?, 'failed', 'same', ?, ?)
                """,
                [(f"R{i}", payload, old if i < 500 else bot.now_iso()) for i in range(2500)],
            )
        conn.close()

        result = bot.maintain_payment_verification_logs(compact=True)
        assert result["remaining"] == 1000, result
        assert result["vacuumed"] is True, result
        assert int(result["size_after"]) < int(result["size_before"]), result

        bot.log_payment_check("DUP", 1, "bep20", "failed", "same")
        bot.log_payment_check("DUP", 1, "bep20", "failed", "same")
        conn = bot.get_conn()
        with conn:
            duplicate_count = int(
                conn.execute("SELECT COUNT(*) FROM payment_verification_logs WHERE ref_id = 'DUP'").fetchone()[0]
            )
        conn.close()
        assert duplicate_count == 1, duplicate_count
        print(result)
        print("maintenance test ok")
    finally:
        if os.path.exists(bot.DB_PATH):
            try:
                os.remove(bot.DB_PATH)
            except PermissionError:
                pass


if __name__ == "__main__":
    main()
