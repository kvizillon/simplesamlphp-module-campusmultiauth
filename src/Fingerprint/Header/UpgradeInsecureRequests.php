<?php

declare(strict_types=1);

namespace SimpleSAML\Module\campusmultiauth\Fingerprint\Header;

class UpgradeInsecureRequests extends \SimpleSAML\Module\campusmultiauth\Fingerprint\Header
{
    protected function getHeaderName()
    {
        return 'HTTP_UPGRADE_INSECURE_REQUESTS';
    }
}
