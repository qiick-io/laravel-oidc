<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/*
 * The identity key (issuer, subject) compares byte for byte: an OIDC `sub` is
 * an opaque, case-sensitive string (OIDC Core 2), and so is the path of an
 * issuer URL. The usual collations of the MySQL family (Laravel's default
 * utf8mb4_unicode_ci, the servers' utf8mb4_0900_ai_ci and utf8mb4_general_ci)
 * compare both case-insensitively, so `AbcSubject` and `abcsubject` were one
 * identity: the lookup returned the other user's identity, and the unique
 * index refused to store the second.
 *
 * A collation, not a binary column type: VARBINARY would become `bytea` on
 * PostgreSQL, which PDO returns as a stream instead of a string. PostgreSQL
 * and SQLite already compare text byte for byte, so this does nothing there.
 *
 * utf8mb4_bin is PAD SPACE on both engines, so `sub ` still equals `sub`. The
 * NO PAD binary collation has a different name on each (utf8mb4_0900_bin,
 * utf8mb4_nopad_bin), so that hole is closed where the `sub` enters the
 * package instead: IdTokenValidatorService and BackChannelLogoutService
 * refuse a `sub` that is not trimmed, on every database.
 */
return new class extends Migration
{
    public function up(): void
    {
        $this->redefineIdentityKey(function (Blueprint $table, string $column): void {
            $table->string($column)->charset('utf8mb4')->collation('utf8mb4_bin')->change();
        });
    }

    /**
     * Back to the table's default collation, which compares the key
     * case-insensitively again.
     */
    public function down(): void
    {
        $this->redefineIdentityKey(function (Blueprint $table, string $column): void {
            $table->string($column)->change();
        });
    }

    /**
     * @param  Closure(Blueprint, string): void  $redefineColumn
     */
    private function redefineIdentityKey(Closure $redefineColumn): void
    {
        if (! in_array(Schema::getConnection()->getDriverName(), ['mysql', 'mariadb'], true)) {
            return;
        }

        Schema::table('user_identities', function (Blueprint $table) use ($redefineColumn): void {
            $redefineColumn($table, 'issuer');
            $redefineColumn($table, 'subject');
        });
    }
};
