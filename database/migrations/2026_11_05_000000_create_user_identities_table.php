<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/*
 * One row per SSO identity linked to a local user. The identity key is the
 * pair (issuer, subject), never the email, so several IdPs and an IdP change
 * are possible. Both are at most 255 characters (OIDC Core 2 for `sub`).
 *
 * The identity key compares byte for byte: an OIDC `sub` is an opaque,
 * case-sensitive string (OIDC Core 2), and so is the path of an issuer URL.
 * The usual collations of the MySQL family (Laravel's default
 * utf8mb4_unicode_ci, the servers' utf8mb4_0900_ai_ci and utf8mb4_general_ci)
 * compare both case-insensitively, so `AbcSubject` and `abcsubject` would be
 * one identity: the lookup would return the other user's identity, and the
 * unique index would refuse to store the second. On MySQL and MariaDB both
 * columns therefore use utf8mb4_bin.
 *
 * A collation, not a binary column type: VARBINARY would become `bytea` on
 * PostgreSQL, which PDO returns as a stream instead of a string. PostgreSQL
 * and SQLite already compare text byte for byte, so they keep the default.
 *
 * utf8mb4_bin is PAD SPACE on both engines, so `sub ` still equals `sub`. The
 * NO PAD binary collation has a different name on each (utf8mb4_0900_bin,
 * utf8mb4_nopad_bin), so that hole is closed where the `sub` enters the
 * package instead: IdTokenValidatorService and BackChannelLogoutService
 * refuse a `sub` that is not trimmed, on every database.
 *
 * This was a separate forward migration in beta.2 to beta.4. It is folded
 * here because the package is not stable yet: until 1.0.0, schema changes
 * edit the create migration (knowledge decision
 * 2026-11-22-package-migrations-before-stable).
 */
return new class extends Migration
{
    public function up(): void
    {
        $usersTable = config('oidc.users.table', 'users');
        $isMysqlFamily = in_array(Schema::getConnection()->getDriverName(), ['mysql', 'mariadb'], true);

        Schema::create('user_identities', function (Blueprint $table) use ($usersTable, $isMysqlFamily): void {
            $table->id();
            $table->foreignId('user_id')->constrained(is_string($usersTable) ? $usersTable : 'users')->cascadeOnDelete();
            $issuer = $table->string('issuer');
            $subject = $table->string('subject');

            if ($isMysqlFamily) {
                $issuer->charset('utf8mb4')->collation('utf8mb4_bin');
                $subject->charset('utf8mb4')->collation('utf8mb4_bin');
            }

            $table->string('email_at_link')->nullable();
            $table->timestamp('last_login_at')->nullable();
            $table->timestamps();

            $table->unique(['issuer', 'subject']);
            $table->index(['user_id', 'issuer']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('user_identities');
    }
};
