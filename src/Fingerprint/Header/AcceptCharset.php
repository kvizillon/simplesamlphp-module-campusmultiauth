<?php

declare(strict_types=1);

namespace SimpleSAML\Module\campusmultiauth\Fingerprint\Header;

class AcceptCharset extends \SimpleSAML\Module\campusmultiauth\Fingerprint\Header
{
    protected function getHeaderName()
    {
        return 'HTTP_ACCEPT_CHARSET';
    }
}
