<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/*
 * Durable store for validated OIDC logout revocations (standards review M10).
 * The cache is only an accelerator: a miss never means "not revoked", and a
 * failed table read fails closed (session treated as revoked).
 *
 * `issuer`, `sid`, `sub` and `jti` compare byte for byte on MySQL/MariaDB
 * (utf8mb4_bin), matching user_identities. Unique (issuer, jti) is the BCL
 * §2.6 replay check; several NULL jti rows are allowed (front-channel).
 *
 * expires_at is dateTime, not timestamp: it is a future pruning date
 * (knowledge 2026-11-20 Core hardening).
 */
return new class extends Migration
{
    public function up(): void
    {
        $isMysqlFamily = in_array(Schema::getConnection()->getDriverName(), ['mysql', 'mariadb'], true);

        Schema::create('oidc_logout_revocations', function (Blueprint $table) use ($isMysqlFamily): void {
            $table->id();
            $issuer = $table->string('issuer');
            $sessionId = $table->string('sid')->nullable();
            $subject = $table->string('sub')->nullable();
            $tokenId = $table->string('jti')->nullable();
            // The digest survives scrubbing the raw token ID, preserving replay protection.
            $table->char('replay_key', 64)->nullable();

            if ($isMysqlFamily) {
                $issuer->charset('utf8mb4')->collation('utf8mb4_bin');
                $sessionId->charset('utf8mb4')->collation('utf8mb4_bin');
                $subject->charset('utf8mb4')->collation('utf8mb4_bin');
                $tokenId->charset('utf8mb4')->collation('utf8mb4_bin');
            }

            $table->string('channel', 16)->default('backchannel');
            $table->timestamp('received_at');
            $table->dateTime('expires_at');
            $table->json('metadata')->nullable();
            $table->timestamps();

            $table->index(['issuer', 'sid']);
            $table->index(['issuer', 'sub']);
            $table->unique(['issuer', 'jti']);
            $table->unique(['issuer', 'replay_key']);
            $table->index(['expires_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('oidc_logout_revocations');
    }
};
