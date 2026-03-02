<?php

declare(strict_types=1);

namespace SimpleSAML\Module\campusmultiauth\Data;

interface Storage
{
    public function __construct();

    /**
     * Null if user has none, URL otherwise.
     */
    public function getSecurityImageOfUser(string $uid): ?string;

    /**
     * Null if user has none, text otherwise.
     */
    public function getAlternativeTextOfUser(string $uid): ?string;

    /**
     * False if not found (should not happen), counter otherwise.
     */
    public function getCookieCounter(string $uid, int $id): ?int;

    /**
     * Increment a counter for a user. Returns the cookie id.
     */
    public function increaseCookieCounter(string $uid, ?int $id): ?int;
}
