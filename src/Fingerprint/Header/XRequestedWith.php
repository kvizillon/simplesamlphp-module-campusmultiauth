<?php

declare(strict_types=1);

namespace SimpleSAML\Module\campusmultiauth\Fingerprint\Header;

class XRequestedWith extends \SimpleSAML\Module\campusmultiauth\Fingerprint\Header
{
    protected function getHeaderName()
    {
        return 'HTTP_X_REQUESTED_WITH';
    }
}
