<?php

declare(strict_types=1);

namespace SimpleSAML\Module\campusmultiauth\Fingerprint\Header;

class Connection extends \SimpleSAML\Module\campusmultiauth\Fingerprint\Header
{
    protected function getHeaderName()
    {
        return 'HTTP_CONNECTION';
    }
}
