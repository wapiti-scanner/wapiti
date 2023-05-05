<?php
/**
 * This file is meant to be the home for any function handling cookies that can
 * be accessed anywhere within Jetpack.
 *
 * This file is loaded whether or not Jetpack is connected to WP.com.
 *
 * @package automattic/jetpack
 */

/**
 * A PHP 5.X compatible version of the array argument version of PHP 7.3's setcookie().
 *
 * Useful for setting SameSite cookies in PHP 7.2 or earlier.
 *
 * @param string $name    Name of the cookie.
 * @param string $value   Value of the cookie.
 * @param array  $options Options to include with the cookie.
 * @return bool False when error happens, other wise true.
 */
function jetpack_shim_setcookie( $name, $value, $options ) {
	$not_allowed_chars = ",; \t\r\n\013\014";

	if ( false !== strpbrk( $name, $not_allowed_chars ) ) {
		return false;
	}

	if ( headers_sent() ) {
		return false;
	}

	$cookie = 'Set-Cookie: ' . $name . '=' . rawurlencode( $value ) . '; ';

	if ( ! empty( $options['expires'] ) ) {
		$cookie_date = gmdate( 'D, d M Y H:i:s \G\M\T', $options['expires'] );
		$cookie     .= sprintf( 'expires=%s', $cookie_date ) . ';';
	}

	if ( ! empty( $options['secure'] ) && true === $options['secure'] ) {
		$cookie .= 'secure; ';
	}

	if ( ! empty( $options['httponly'] ) && true === $options['httponly'] ) {
		$cookie .= 'HttpOnly; ';
	}

	if ( ! empty( $options['domain'] ) && is_string( $options['domain'] ) ) {
		if ( false !== strpbrk( $options['domain'], $not_allowed_chars ) ) {
			return false;
		}
		$cookie .= sprintf( 'domain=%s', $options['domain'] . '; ' );
	}

	if ( ! empty( $options['path'] ) && is_string( $options['path'] ) ) {
		if ( false !== strpbrk( $options['path'], $not_allowed_chars ) ) {
			return false;
		}
		$cookie .= sprintf( 'path=%s', $options['path'] . '; ' );
	}

	if ( ! empty( $options['samesite'] ) && is_string( $options['samesite'] ) ) {
		$cookie .= sprintf( 'SameSite=%s', $options['samesite'] . '; ' );
	}

	$cookie = trim( $cookie );
	$cookie = trim( $cookie, ';' );
	header( $cookie, false );

	return true;
}
