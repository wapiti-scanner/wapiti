<?php
/**
 * Simple semver version handling.
 *
 * We use this instead of something like `composer/semver` to avoid
 * plugins needing to include yet-another dependency package. The
 * amount of code we need here is pretty small.
 *
 * We use this instead of PHP's `version_compare()` because that doesn't
 * handle prerelease versions in the way anyone other than PHP devs would
 * expect, and silently breaks on various unexpected input.
 *
 * @package automattic/jetpack-assets
 */

namespace Automattic\Jetpack\Assets;

use InvalidArgumentException;

/**
 * Simple semver version handling.
 */
class Semver {
	/**
	 * Parse a semver version.
	 *
	 * @param string $version Version.
	 * @return array With components:
	 *  - major: (int) Major version.
	 *  - minor: (int) Minor version.
	 *  - patch: (int) Patch version.
	 *  - version: (string) Major.minor.patch.
	 *  - prerelease: (string|null) Pre-release string.
	 *  - buildinfo: (string|null) Build metadata string.
	 * @throws InvalidArgumentException If the version number is not in a recognized format.
	 */
	public static function parse( $version ) {
		// This is slightly looser than the official version from semver.org, in that leading zeros are allowed.
		if ( ! preg_match( '/^(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)(?:-(?P<prerelease>(?:[0-9a-zA-Z-]+)(?:\.(?:[0-9a-zA-Z-]+))*))?(?:\+(?P<buildinfo>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$/', $version, $m ) ) {
			throw new InvalidArgumentException( "Version number \"$version\" is not in a recognized format." );
		}
		$info = array(
			'major'      => (int) $m['major'],
			'minor'      => (int) $m['minor'],
			'patch'      => (int) $m['patch'],
			'version'    => sprintf( '%d.%d.%d', $m['major'], $m['minor'], $m['patch'] ),
			'prerelease' => isset( $m['prerelease'] ) && '' !== $m['prerelease'] ? $m['prerelease'] : null,
			'buildinfo'  => isset( $m['buildinfo'] ) && '' !== $m['buildinfo'] ? $m['buildinfo'] : null,
		);

		if ( null !== $info['prerelease'] ) {
			$sep        = '';
			$prerelease = '';
			foreach ( explode( '.', $info['prerelease'] ) as $part ) {
				if ( ctype_digit( $part ) ) {
					$part = (int) $part;
				}
				$prerelease .= $sep . $part;
				$sep         = '.';
			}
			$info['prerelease'] = $prerelease;
		}

		return $info;
	}

	/**
	 * Compare two version numbers.
	 *
	 * @param string $a First version.
	 * @param string $b Second version.
	 * @return int Less than, equal to, or greater than 0 depending on whether `$a` is less than, equal to, or greater than `$b`.
	 * @throws InvalidArgumentException If the version numbers are not in a recognized format.
	 */
	public static function compare( $a, $b ) {
		$aa = self::parse( $a );
		$bb = self::parse( $b );
		if ( $aa['major'] !== $bb['major'] ) {
			return $aa['major'] - $bb['major'];
		}
		if ( $aa['minor'] !== $bb['minor'] ) {
			return $aa['minor'] - $bb['minor'];
		}
		if ( $aa['patch'] !== $bb['patch'] ) {
			return $aa['patch'] - $bb['patch'];
		}

		if ( null === $aa['prerelease'] ) {
			return null === $bb['prerelease'] ? 0 : 1;
		}
		if ( null === $bb['prerelease'] ) {
			return -1;
		}

		$aaa = explode( '.', $aa['prerelease'] );
		$bbb = explode( '.', $bb['prerelease'] );
		$al  = count( $aaa );
		$bl  = count( $bbb );
		for ( $i = 0; $i < $al && $i < $bl; $i++ ) {
			$a = $aaa[ $i ];
			$b = $bbb[ $i ];
			if ( ctype_digit( $a ) ) {
				if ( ctype_digit( $b ) ) {
					if ( (int) $a !== (int) $b ) {
						return $a - $b;
					}
				} else {
					return -1;
				}
			} elseif ( ctype_digit( $b ) ) {
				return 1;
			} else {
				$tmp = strcmp( $a, $b );
				if ( 0 !== $tmp ) {
					return $tmp;
				}
			}
		}
		return $al - $bl;
	}

}
