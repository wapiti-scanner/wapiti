<?php

namespace YoastSEO_Vendor\GuzzleHttp\Psr7;

use YoastSEO_Vendor\Psr\Http\Message\UriInterface;
/**
 * Provides methods to determine if a modified URL should be considered cross-origin.
 *
 * @author Graham Campbell
 */
final class UriComparator
{
    /**
     * Determines if a modified URL should be considered cross-origin with
     * respect to an original URL.
     *
     * @return bool
     */
    public static function isCrossOrigin(\YoastSEO_Vendor\Psr\Http\Message\UriInterface $original, \YoastSEO_Vendor\Psr\Http\Message\UriInterface $modified)
    {
        if (\strcasecmp($original->getHost(), $modified->getHost()) !== 0) {
            return \true;
        }
        if ($original->getScheme() !== $modified->getScheme()) {
            return \true;
        }
        if (self::computePort($original) !== self::computePort($modified)) {
            return \true;
        }
        return \false;
    }
    /**
     * @return int
     */
    private static function computePort(\YoastSEO_Vendor\Psr\Http\Message\UriInterface $uri)
    {
        $port = $uri->getPort();
        if (null !== $port) {
            return $port;
        }
        return 'https' === $uri->getScheme() ? 443 : 80;
    }
    private function __construct()
    {
        // cannot be instantiated
    }
}
