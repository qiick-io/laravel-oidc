<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/*
 * One row per SSO identity linked to a local user. The identity key is the
 * pair (issuer, subject), never the email, so several IdPs and an IdP change
 * are possible. Both are at most 255 characters (OIDC Core 2 for `sub`).
 */
return new class extends Migration
{
    public function up(): void
    {
        $usersTable = config('oidc.users.table', 'users');

        Schema::create('user_identities', function (Blueprint $table) use ($usersTable): void {
            $table->id();
            $table->foreignId('user_id')->constrained(is_string($usersTable) ? $usersTable : 'users')->cascadeOnDelete();
            $table->string('issuer');
            $table->string('subject');
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
