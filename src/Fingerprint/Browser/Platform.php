<?php

declare(strict_types=1);

namespace SimpleSAML\Module\campusmultiauth\Fingerprint\Browser;

class Platform extends \SimpleSAML\Module\campusmultiauth\Fingerprint\Browser
{
    protected function getProperty($ua)
    {
        return $ua->platform();
    }
}
