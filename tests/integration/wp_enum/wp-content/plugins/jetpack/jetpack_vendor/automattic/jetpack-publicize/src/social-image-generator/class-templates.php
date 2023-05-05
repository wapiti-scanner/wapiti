<?php
/**
 * Templates class.
 *
 * @package automattic/jetpack-publicize
 */

namespace Automattic\Jetpack\Publicize\Social_Image_Generator;

/**
 * This class is used to get information about templates.
 */
class Templates {
	/**
	 * Available templates.
	 *
	 * @var array
	 */
	const TEMPLATES = array( 'highway', 'dois', 'fullscreen', 'edge' );

	/**
	 * Default template for new posts.
	 *
	 * @var string
	 */
	const DEFAULT_TEMPLATE = 'highway';
}
