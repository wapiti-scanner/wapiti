<?php

namespace YoastSEO_Vendor\WordProof\SDK\Support;

class Template
{
    private static $blocks = [];
    private static $cache_path = 'cache/';
    private static $template_path = 'templates/';
    private static $cache_enabled = \true;
    private static $store_cache = \false;
    public static function setOptions(array $options)
    {
        foreach ($options as $optionName => $optionValue) {
            if (\property_exists(__CLASS__, $optionName)) {
                self::${$optionName} = $optionValue;
            }
        }
    }
    public static function setCachePath($path)
    {
        self::$cache_path = $path;
    }
    public static function setTemplatePath($path)
    {
        self::$template_path = $path;
    }
    public static function render($file, $data = [])
    {
        \ob_start();
        self::view($file, $data);
        return \ob_get_contents();
    }
    public static function view($file, $data = [])
    {
        if (self::$store_cache) {
            $cached_file = self::cache($file);
            \extract($data, \EXTR_SKIP);
            require $cached_file;
        } else {
            $code = self::includeFiles($file);
            $code = self::compileCode($code);
            $code = '?>' . \PHP_EOL . $code . \PHP_EOL . "<?php";
            \extract($data, \EXTR_SKIP);
            eval($code);
        }
    }
    private static function cache($file)
    {
        if (!\file_exists(self::$cache_path)) {
            \mkdir(self::$cache_path, 0744);
        }
        $cached_file = self::$cache_path . \str_replace(['/', '.html'], ['_', ''], $file . '.php');
        if (!self::$cache_enabled || !\file_exists($cached_file) || \filemtime($cached_file) < \filemtime($file)) {
            $code = self::includeFiles($file);
            $code = self::compileCode($code);
            \file_put_contents($cached_file, '<?php class_exists(\'' . __CLASS__ . '\') or exit; ?>' . \PHP_EOL . $code);
        }
        return $cached_file;
    }
    public static function clearCache()
    {
        foreach (\glob(self::$cache_path . '*') as $file) {
            \unlink($file);
        }
    }
    private static function compileCode($code)
    {
        $code = self::compileBlock($code);
        $code = self::compileYield($code);
        $code = self::compileEscapedEchos($code);
        $code = self::compileEchos($code);
        $code = self::compilePHP($code);
        return $code;
    }
    private static function includeFiles($file)
    {
        $code = \file_get_contents(self::$template_path . $file);
        \preg_match_all('/{% ?(extends|include) ?\'?(.*?)\'? ?%}/i', $code, $matches, \PREG_SET_ORDER);
        foreach ($matches as $value) {
            $code = \str_replace($value[0], self::includeFiles($value[2]), $code);
        }
        $code = \preg_replace('/{% ?(extends|include) ?\'?(.*?)\'? ?%}/i', '', $code);
        return $code;
    }
    private static function compilePHP($code)
    {
        return \preg_replace('~{%\\s*(.+?)\\s*%}~is', '<?php $1 ?>', $code);
    }
    private static function compileEchos($code)
    {
        return \preg_replace('~{{\\s*(.+?)\\s*}}~is', '<?php echo $1 ?>', $code);
    }
    private static function compileEscapedEchos($code)
    {
        return \preg_replace('~{{{\\s*(.+?)\\s*}}}~is', '<?php echo htmlentities($1, ENT_QUOTES, \'UTF-8\') ?>', $code);
    }
    private static function compileBlock($code)
    {
        \preg_match_all('/{% ?block ?(.*?) ?%}(.*?){% ?endblock ?%}/is', $code, $matches, \PREG_SET_ORDER);
        foreach ($matches as $value) {
            if (!\array_key_exists($value[1], self::$blocks)) {
                self::$blocks[$value[1]] = '';
            }
            if (\strpos($value[2], '@parent') === \false) {
                self::$blocks[$value[1]] = $value[2];
            } else {
                self::$blocks[$value[1]] = \str_replace('@parent', self::$blocks[$value[1]], $value[2]);
            }
            $code = \str_replace($value[0], '', $code);
        }
        return $code;
    }
    private static function compileYield($code)
    {
        foreach (self::$blocks as $block => $value) {
            $code = \preg_replace('/{% ?yield ?' . $block . ' ?%}/', $value, $code);
        }
        $code = \preg_replace('/{% ?yield ?(.*?) ?%}/i', '', $code);
        return $code;
    }
}
