<?php

declare(strict_types=1);

namespace Qiick\Oidc\Models;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Qiick\Oidc\Models\Concerns\GuardsIdByDefaultTrait;

/**
 * An SSO identity (issuer, subject) linked to a local user.
 *
 * The bigint `id` stays the primary key so legacy-subject imports keep working.
 * `public_id` is the external UUID v7 (fleet schema; standards review M3).
 *
 * @property int $id
 * @property string $public_id
 * @property int $user_id
 * @property string $issuer
 * @property string $subject
 * @property string|null $subject_type
 * @property string|null $provider_key
 * @property string|null $link_method
 * @property string|null $email_at_link
 * @property bool|null $email_verified_at_link
 * @property string|null $preferred_username_at_link
 * @property string|null $name_at_link
 * @property CarbonImmutable|null $last_login_at
 * @property CarbonImmutable|null $last_auth_time_at
 * @property string|null $last_acr
 * @property list<string>|null $last_amr
 * @property string|null $last_id_token_alg
 * @property int $format_version
 * @property array<string, mixed>|null $metadata
 * @property CarbonImmutable|null $created_at
 * @property CarbonImmutable|null $updated_at
 * @property-read (Model&Authenticatable)|null $user
 */
class UserIdentity extends Model
{
    use GuardsIdByDefaultTrait;
    use HasUuids;

    protected $table = 'user_identities';

    /**
     * A new row starts at format_version 1; attributes an app subclass
     * declares are kept.
     *
     * @param  array<string, mixed>  $attributes
     */
    public function __construct(array $attributes = [])
    {
        $this->attributes += ['format_version' => 1];

        parent::__construct($attributes);
    }

    /**
     * External id only; the auto-increment `id` stays the primary key (M3).
     *
     * @return list<string>
     */
    public function uniqueIds(): array
    {
        return ['public_id'];
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'email_verified_at_link' => 'boolean',
            'last_login_at' => 'immutable_datetime',
            'last_auth_time_at' => 'immutable_datetime',
            'last_amr' => 'array',
            'format_version' => 'integer',
            'metadata' => 'array',
            'created_at' => 'immutable_datetime',
            'updated_at' => 'immutable_datetime',
        ];
    }

    /**
     * @return BelongsTo<Model, $this>
     */
    public function user(): BelongsTo
    {
        return $this->belongsTo(self::userModel(), 'user_id');
    }

    /**
     * The app's user model: `oidc.users.model`, else `auth.providers.users.model`.
     *
     * @return class-string<Model>
     */
    public static function userModel(): string
    {
        $model = config('oidc.users.model') ?? config('auth.providers.users.model');

        if (! is_string($model) || ! is_a($model, Model::class, true) || ! is_a($model, Authenticatable::class, true)) {
            throw new \LogicException('oidc.users.model must be an Eloquent model that implements Authenticatable.');
        }

        return $model;
    }
}
