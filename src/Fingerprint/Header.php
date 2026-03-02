<?php

declare(strict_types=1);

namespace SimpleSAML\Module\campusmultiauth\Fingerprint;

abstract class Header extends \SimpleSAML\Module\campusmultiauth\Fingerprint
{
    public function getValue()
    {
        return isset($_SERVER[$this->getHeaderName()]) ? $_SERVER[$this->getHeaderName()] : false;
    }

    /**
     * @returns string
     */
    abstract protected function getHeaderName();
}
