<?php

declare(strict_types=1);

namespace SimpleSAML\Module\campusmultiauth\Fingerprint;

use donatj\UserAgent\UserAgentParser;

abstract class Browser extends \SimpleSAML\Module\campusmultiauth\Fingerprint
{
    public function getValue()
    {
        $ua = self::getBrowserInfo();

        return $this->getProperty($ua);
    }

    abstract protected function getProperty($ua);

    private static function getBrowserInfo()
    {
        $parser = new UserAgentParser();

        return $parser->parse();
    }
}
