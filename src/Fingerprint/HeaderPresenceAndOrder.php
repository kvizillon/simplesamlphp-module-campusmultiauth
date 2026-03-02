<?php

declare(strict_types=1);

namespace SimpleSAML\Module\campusmultiauth\Fingerprint;

class HeaderPresenceAndOrder extends \SimpleSAML\Module\campusmultiauth\Fingerprint
{
    private const HEADERS = ['client-ip', 'x-forwarded-for', 'x-forwarded', 'x-cluster-client-ip', 'forwarded-for',
        'forwarded', 'via', 'accept', 'accept-charset', 'accept-encoding', 'accept-language', 'connection',
        'cookie', 'content-length', 'host', 'referer', 'user-agent', 'x-requested-with', 'dnt',
        'upgrade-insecure-requests', ];

    public function getValue()
    {
        return array_keys(
            array_filter(
                getallheaders(),
                function ($var) {
                    return in_array(strtolower($var), self::HEADERS, true);
                },
                ARRAY_FILTER_USE_KEY
            )
        );
    }
}
