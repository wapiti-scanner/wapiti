<?php
/**
 * Recipe Block.
 *
 * @since 11.1
 *
 * @package automattic/jetpack
 */

use Automattic\Jetpack\Blocks;

Blocks::jetpack_register_block(
	'jetpack/recipe',
	array(
		'render_callback' => array( 'Automattic\\Jetpack\\Extensions\\Recipe\\Jetpack_Recipe_Block', 'render' ),
	)
);

Blocks::jetpack_register_block(
	'jetpack/recipe-details',
	array(
		'parent' => array( 'jetpack/recipe' ),
	)
);

Blocks::jetpack_register_block(
	'jetpack/recipe-hero',
	array(
		'parent'          => array( 'jetpack/recipe' ),
		'render_callback' => array( 'Automattic\\Jetpack\\Extensions\\Recipe\\Jetpack_Recipe_Block', 'render_hero' ),
	)
);

Blocks::jetpack_register_block(
	'jetpack/recipe-ingredients-list',
	array(
		'parent' => array( 'jetpack/recipe' ),
	)
);

Blocks::jetpack_register_block(
	'jetpack/recipe-ingredient-item',
	array(
		'parent' => array( 'jetpack/recipe' ),
	)
);

Blocks::jetpack_register_block(
	'jetpack/recipe-steps',
	array(
		'parent' => array( 'jetpack/recipe' ),
	)
);

Blocks::jetpack_register_block(
	'jetpack/recipe-step',
	array(
		'parent'          => array( 'jetpack/recipe' ),
		'render_callback' => array( 'Automattic\\Jetpack\\Extensions\\Recipe\\Jetpack_Recipe_Block', 'render_step' ),
	)
);

require_once __DIR__ . '/class-jetpack-recipe-block.php';
