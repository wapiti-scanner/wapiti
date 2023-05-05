<?php
require_once __DIR__ . '/../src/MultiStringMatcher.php';
require_once __DIR__ . '/../src/MultiStringReplacer.php';

use AhoCorasick\MultiStringReplacer;

if ( !file_exists( __DIR__ . '/23835-0.txt' ) ) {
	die( 'Please download http://www.gutenberg.org/files/23835/23835-0.txt' );
}

if ( !file_exists( __DIR__ . '/ZhConversion.php' ) ) {
	die( 'You need ZhConversion.php, from http://git.io/vIMst' );
}

require_once __DIR__ . '/ZhConversion.php';

$text = file_get_contents( __DIR__ . '/23835-0.txt' );

$status = 0;
$expected = strtr( $text, $zh2Hant );

echo "MultiStringReplacer::searchAndReplace(): ";
$replacer = new MultiStringReplacer( $zh2Hant );
if ( $replacer->searchAndReplace( $text ) !== $expected ) {
	echo "ERROR\n";
	$status = 1;
} else {
	echo "OK\n";
}

if ( function_exists( 'fss_exec_replace' ) ) {
	echo "fss_exec_replace(): ";
	$fss = fss_prep_replace( $zh2Hant );
	if ( fss_exec_replace( $fss, $text ) !== $expected ) {
		echo "ERROR\n";
		$status = 1;
	} else {
		echo "OK\n";
	}
}

exit( $status );
