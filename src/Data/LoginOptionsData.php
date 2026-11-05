<?php

declare(strict_types=1);

namespace Qiick\Oidc\Data;

/**
 * What the app's login page needs to know, ready to share as Inertia or
 * Blade props.
 */
final readonly class LoginOptionsData
{
    public function __construct(
        public bool $isSsoAvailable,
        public bool $isSsoOnly,
        public bool $isPasswordLoginVisible,
        public string $buttonLabel,
        public ?string $redirectUrl,
    ) {}

    /**
     * @return array{isSsoAvailable: bool, isSsoOnly: bool, isPasswordLoginVisible: bool, buttonLabel: string, redirectUrl: string|null}
     */
    public function toArray(): array
    {
        return [
            'isSsoAvailable' => $this->isSsoAvailable,
            'isSsoOnly' => $this->isSsoOnly,
            'isPasswordLoginVisible' => $this->isPasswordLoginVisible,
            'buttonLabel' => $this->buttonLabel,
            'redirectUrl' => $this->redirectUrl,
        ];
    }
}
