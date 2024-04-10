<?php

declare(strict_types=1);

namespace thisispiers\ContentSecurityPolicy;

class ContentSecurityPolicy
{
    /** @var array<string, array<string>> */
    private static array $csp = [];

    private static function setDefaultDirectives(): void {
        if (empty(self::$csp)) {
            self::$csp = [
                'default-src' => [
                    "'self'",
                    "'unsafe-inline'",
                    "data:",
                ],
                'frame-ancestors' => [
                    "'self'",
                ],
            ];
        }
    }

    public static function addDirective(string $directive, string $value): void
    {
        self::setDefaultDirectives();
        if (!isset(self::$csp[$directive])) {
            self::$csp[$directive] = [];
        }
        self::$csp[$directive][] = $value;
    }

    public static function sendHeader(): void {
        if (!empty(self::$csp)) {
            // serialise
            $csp = [];
            foreach (self::$csp as $d => $directive) {
                $directive = array_unique($directive);
                $csp[] = $d . ' ' . implode(' ', $directive);
            }
            $csp = implode('; ', $csp);

            header('Content-Security-Policy: ' . $csp);
        }
    }
}