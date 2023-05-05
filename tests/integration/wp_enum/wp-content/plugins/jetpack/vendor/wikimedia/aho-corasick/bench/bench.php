<?php
require_once __DIR__ . '/../src/MultiStringMatcher.php';
require_once __DIR__ . '/../src/MultiStringReplacer.php';

use AhoCorasick\MultiStringReplacer;

if ( !file_exists( __DIR__ . '/23835-0.txt' ) ) {
	die( "Please download http://www.gutenberg.org/files/23835/23835-0.txt\n" );
}

if ( !file_exists( __DIR__ . '/ZhConversion.php' ) ) {
	die( "You need ZhConversion.php, from " .
		"https://github.com/wikimedia/mediawiki/blob/master/includes/ZhConversion.php\n" );
}

require_once __DIR__ . '/ZhConversion.php';

$text = file_get_contents( __DIR__ . '/23835-0.txt' );

$options = getopt( '', [ 'count:', 'input:', 'profile', 'fss', 'msr', 'strtr' ] );
$text = file_get_contents( isset( $options['input'] ) ? $options['input'] : 'SueiTangYanYi.txt' );
$loops = isset( $options['count'] ) ? intval( $options['count'] ) : 5;
if ( !isset( $options['fss'] ) && !isset( $options['msr'] ) && !isset( $options['strtr'] ) ) {
	$options['fss'] = true;
	$options['msr'] = true;
	$options['strtr'] = true;
}
$profile = false;
if ( isset( $options['profile'] ) ) {
	$profile = true;
	$options['msr'] = true;
	unset( $options['fss'] );
	unset( $options['strtr'] );
}

if ( isset( $options['msr'] ) ) {
	$replacer = new MultiStringReplacer( $zh2Hant );
	if ( $profile ) {
		xhprof_enable( XHPROF_FLAGS_CPU );
	}
	$startTime = microtime( true );
	for ( $i = 0; $i < $loops; $i++ ) {
		$replacer->searchAndReplace( $text );
	}
	$endTime = microtime( true );
	$wallTime = 1000 * ( ( $endTime - $startTime ) / $loops );
	printf( "%-'.40s %.2fms\n", 'MultiStringRepeater::searchAndReplace(): ', $wallTime );
	if ( $profile ) {
		$profile = xhprof_disable();
		foreach ( $profile as $func => $data ) {
			printf( "%s: %.2f\n", $func, $data['cpu'] / $data['ct'] );
		}
	}
}

if ( function_exists( 'fss_prep_replace' ) && isset( $options['fss'] ) ) {
	$fss = fss_prep_replace( $zh2Hant );
	$startTime = microtime( true );
	for ( $i = 0; $i < $loops; $i++ ) {
		fss_exec_replace( $fss, $text );
	}
	$endTime = microtime( true );
	$wallTime = 1000 * ( ( $endTime - $startTime ) / $loops );
	printf( "%-'.40s %.2fms\n", 'fss_exec_replace(): ', $wallTime );
}

if ( isset( $options['strtr'] ) ) {
	$startTime = microtime( true );
	for ( $i = 0; $i < $loops; $i++ ) {
		strtr( $text, $zh2Hant );
	}
	$endTime = microtime( true );
	$wallTime = 1000 * ( ( $endTime - $startTime ) / $loops );
	printf( "%-'.40s %.2fms\n", 'strtr(): ', $wallTime );
}
