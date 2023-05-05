<?php

namespace YoastSEO_Vendor\WordProof\SDK\Helpers;

use YoastSEO_Vendor\WordProof\SDK\Config\RoutesConfig;
class RestApiHelper
{
    private static function buildPath($endpoint)
    {
        return 'wordproof/v1' . $endpoint;
    }
    public static function getNamespace()
    {
        return self::buildPath('');
    }
    public static function route($slug)
    {
        $routes = \YoastSEO_Vendor\WordProof\SDK\Config\RoutesConfig::get();
        if (isset($routes[$slug])) {
            return $routes[$slug];
        }
        throw new \Exception('Route slug does not exist.');
    }
    public static function endpoint($slug)
    {
        $route = self::route($slug);
        if (isset($route['endpoint'])) {
            return $route['endpoint'];
        }
        throw new \Exception('Endpoint for route does not exist.');
    }
    public static function getRestRoute($slug, $params = [])
    {
        $url = \get_rest_url(null, self::buildPath(self::endpoint($slug)));
        \preg_match_all("/\\(.+?\\)/", $url, $matches);
        if (!isset($matches) || !isset($matches[0])) {
            return $url;
        }
        if (!\is_array($params) || \count($params) !== \count($matches[0])) {
            return $url;
        }
        foreach ($matches[0] as $index => $match) {
            $url = \str_replace($match, $params[$index], $url);
        }
        return $url;
    }
}
