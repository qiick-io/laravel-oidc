<?php

declare(strict_types=1);

namespace Qiick\Oidc\Models;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;

/**
 * An SSO identity (issuer, subject) linked to a local user.
 *
 * @property int $id
 * @property int $user_id
 * @property string $issuer
 * @property string $subject
 * @property string|null $email_at_link
 * @property Carbon|null $last_login_at
 * @property-read (Model&Authenticatable)|null $user
 */
class UserIdentity extends Model
{
    protected $table = 'user_identities';

    protected $guarded = ['id'];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'last_login_at' => 'datetime',
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
