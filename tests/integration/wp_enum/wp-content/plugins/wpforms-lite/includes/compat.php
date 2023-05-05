<?php
/**
 * WordPress core function polyfill for WordPress 5.2 - 5.4.
 *
 * @since 1.7.6
 */
if ( ! function_exists( 'wp_get_environment_type' ) ) {
	/**
	 * Retrieves the current environment type.
	 *
	 * The type can be set via the `WP_ENVIRONMENT_TYPE` global system variable,
	 * or a constant of the same name.
	 *
	 * Possible values are 'local', 'development', 'staging', and 'production'.
	 * If not set, the type defaults to 'production'.
	 *
	 * @return string The current environment type.
	 */
	function wp_get_environment_type() { // phpcs:ignore Generic.Metrics.CyclomaticComplexity.TooHigh, WPForms.Comments.SinceTag.MissingSince

		static $current_env = '';

		if ( ! defined( 'WP_RUN_CORE_TESTS' ) && $current_env ) {
			return $current_env;
		}

		$wp_environments = [
			'local',
			'development',
			'staging',
			'production',
		];

		// Add a note about the deprecated WP_ENVIRONMENT_TYPES constant.
		if ( defined( 'WP_ENVIRONMENT_TYPES' ) && function_exists( '_deprecated_argument' ) ) {
			// phpcs:disable WPForms.PHP.ValidateDomain.InvalidDomain
			if ( function_exists( '__' ) ) {
				/* translators: %s: WP_ENVIRONMENT_TYPES. */
				$message = sprintf( __( 'The %s constant is no longer supported.' ), 'WP_ENVIRONMENT_TYPES' );
			} else {
				$message = sprintf( 'The %s constant is no longer supported.', 'WP_ENVIRONMENT_TYPES' );
			}
			// phpcs:enable WPForms.PHP.ValidateDomain.InvalidDomain

			_deprecated_argument(
				'define()',
				'5.5.1',
				// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				$message
			);
		}

		// Check if the environment variable has been set, if `getenv` is available on the system.
		if ( function_exists( 'getenv' ) ) {
			$has_env = getenv( 'WP_ENVIRONMENT_TYPE' );

			if ( $has_env !== false ) {
				$current_env = $has_env;
			}
		}

		// Fetch the environment from a constant, this overrides the global system variable.
		if ( defined( 'WP_ENVIRONMENT_TYPE' ) ) {
			$current_env = WP_ENVIRONMENT_TYPE;
		}

		// Make sure the environment is an allowed one, and not accidentally set to an invalid value.
		if ( ! in_array( $current_env, $wp_environments, true ) ) {
			$current_env = 'production';
		}

		return $current_env;
	}
}
