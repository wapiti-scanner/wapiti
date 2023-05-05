<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * This file contains PHPUnit tests for the Post_List class.
 * To run the package unit tests:
 * - go the post-list folder "cd projects/packages/post-list"
 * - run the command "composer test-php"
 *
 * @package automattic/jetpack-post-list
 */

namespace Automattic\Jetpack\Post_List;

use WorDBless\BaseTestCase;

/**
 * PHPUnit tests for the Post_List class.
 *
 * @package automattic/jetpack-post-list
 */
class Test_Post_List extends BaseTestCase {

	/**
	 * Post_List::get_instance() should return and instance of the Post_List class.
	 */
	public function test_get_instance() {
		$this->assertInstanceOf( Post_List::class, Post_List::get_instance() );
	}

	/**
	 * Test the register() method.
	 */
	public function test_register() {
		$post_list = Post_List::get_instance();

		// did_action() Retrieves the number of times an action has been fired during the current request.
		// Assert our action hasn't been fired yet.
		$this->assertSame( 0, did_action( 'jetpack_on_posts_list_init' ) );

		// Assert our action has not been added yet.
		$this->assertFalse( has_action( 'admin_enqueue_scripts', array( $post_list, 'enqueue_scripts' ) ) );
		$this->assertFalse( has_action( 'current_screen', array( $post_list, 'add_filters_and_actions_for_screen' ) ) );

		// Set up our action callbacks using the register() method.
		$post_list->register();

		// Assert the action was added.
		$this->assertNotFalse( has_action( 'admin_enqueue_scripts', array( $post_list, 'enqueue_scripts' ) ) );
		$this->assertNotFalse( has_action( 'current_screen', array( $post_list, 'add_filters_and_actions_for_screen' ) ) );

		// Confirm it was only fired once even though we call it twice.
		$post_list->register();
		$this->assertSame( 1, did_action( 'jetpack_on_posts_list_init' ) );
	}

	/**
	 * Test the enqueue_scripts() method.
	 */
	public function test_enqueue_scripts() {
		$post_list = Post_List::get_instance();

		// Confirm that our style, filter, and action have not been added before the enqueue_scripts() method call.
		$this->assertFalse( wp_style_is( 'jetpack_posts_list_ui_style' ) );

		$post_list->enqueue_scripts( 'edit.php' );

		// Assert that our style, filter, and action has been added.
		$this->assertTrue( wp_style_is( 'jetpack_posts_list_ui_style' ) );
	}

	/**
	 * As a control when testing add_filters_and_actions_for_screen() make sure it always starts clean.
	 */
	private function confirm_add_filters_and_actions_for_screen_starts_clean() {
		$this->assertFalse( has_filter( 'manage_posts_columns' ) );
		$this->assertFalse( has_action( 'manage_posts_custom_column' ) );
		$this->assertFalse( has_filter( 'manage_pages_columns' ) );
		$this->assertFalse( has_action( 'manage_pages_custom_column' ) );
		$this->assertFalse( has_action( 'post_row_actions' ) );
		$this->assertFalse( has_action( 'page_row_actions' ) );
	}

	/**
	 * Test add_filters_and_actions_for_screen() with "Pages".
	 * Thumbnail should show up on "Pages", but Share should not, because 'publicize' is not supported on "Pages".
	 */
	public function test_add_filters_and_actions_for_screen_thumbnail() {
		$post_list = Post_List::get_instance();

		$this->confirm_add_filters_and_actions_for_screen_starts_clean();

		$current_screen = (object) array(
			'base'      => 'edit',
			'post_type' => 'page',
		);

		// Turn on the flag that allows the Share action if applicable.
		add_filter( 'jetpack_post_list_display_share_action', '__return_true' );

		$post_list->add_filters_and_actions_for_screen( $current_screen );

		// Assert that our style, filter, and action has been added.
		$this->assertTrue( has_filter( 'manage_posts_columns' ) );
		$this->assertTrue( has_action( 'manage_posts_custom_column' ) );
		$this->assertTrue( has_filter( 'manage_pages_columns' ) );
		$this->assertTrue( has_action( 'manage_pages_custom_column' ) );
		$this->assertFalse( has_action( 'post_row_actions' ) );
		$this->assertFalse( has_action( 'page_row_actions' ) );
	}

	/**
	 * Test add_filters_and_actions_for_screen() with a custom post type.
	 * Thumbnail should ONLY show up on "Posts" and "Pages". However, the Share action should show up on custom post
	 * types that support publicize and the block editor.
	 */
	public function test_add_filters_and_actions_for_screen_share() {
		$post_list = Post_List::get_instance();

		$this->confirm_add_filters_and_actions_for_screen_starts_clean();

		// Create a custom post type.
		register_post_type(
			'post_type_we_made_up',
			array(
				'show_in_rest' => true,
				'supports'     => array( 'editor', 'publicize' ),
			)
		);

		// Set the current screen to our custom post type.
		$current_screen = (object) array(
			'base'      => 'edit',
			'post_type' => 'post_type_we_made_up',
		);

		// Turn on the flag that allows the Share action if applicable.
		add_filter( 'jetpack_post_list_display_share_action', '__return_true' );

		$post_list->add_filters_and_actions_for_screen( $current_screen );

		// Assert that only the Share action was enabled.
		$this->assertFalse( has_filter( 'manage_posts_columns' ) );
		$this->assertFalse( has_action( 'manage_posts_custom_column' ) );
		$this->assertFalse( has_filter( 'manage_pages_columns' ) );
		$this->assertFalse( has_action( 'manage_pages_custom_column' ) );
		$this->assertTrue( has_action( 'post_row_actions' ) );
		$this->assertTrue( has_action( 'page_row_actions' ) );
	}

	/**
	 * Test the add_filters_and_actions_for_screen() with "Posts".
	 * The thumbnail and Share action should be available on "Posts".
	 */
	public function test_add_filters_and_actions_for_screen_thumbnail_and_share() {
		$post_list = Post_List::get_instance();

		$this->confirm_add_filters_and_actions_for_screen_starts_clean();

		$current_screen = (object) array(
			'base'      => 'edit',
			'post_type' => 'post',
		);
		add_post_type_support( 'post', 'publicize' );

		// Turn on the flag that allows the Share action if applicable.
		add_filter( 'jetpack_post_list_display_share_action', '__return_true' );

		$post_list->add_filters_and_actions_for_screen( $current_screen );

		// Assert that our style, filter, and action has been added.
		$this->assertTrue( has_filter( 'manage_posts_columns' ) );
		$this->assertTrue( has_action( 'manage_posts_custom_column' ) );
		$this->assertTrue( has_filter( 'manage_pages_columns' ) );
		$this->assertTrue( has_action( 'manage_pages_custom_column' ) );
		$this->assertTrue( has_action( 'post_row_actions' ) );
		$this->assertTrue( has_action( 'page_row_actions' ) );
	}

	/**
	 * Test the add_filters_and_actions_for_screen() with "Posts".
	 * The thumbnail and Share action should be available on "Posts", but we don't set the share flag to true, so only
	 * thumbnails show up.
	 */
	public function test_add_filters_and_actions_for_screen_share_flag_disabled() {
		$post_list = Post_List::get_instance();

		$this->confirm_add_filters_and_actions_for_screen_starts_clean();

		$current_screen = (object) array(
			'base'      => 'edit',
			'post_type' => 'post',
		);
		add_post_type_support( 'post', 'publicize' );

		$post_list->add_filters_and_actions_for_screen( $current_screen );

		// Assert that our style, filter, and action has been added.
		$this->assertTrue( has_filter( 'manage_posts_columns' ) );
		$this->assertTrue( has_action( 'manage_posts_custom_column' ) );
		$this->assertTrue( has_filter( 'manage_pages_columns' ) );
		$this->assertTrue( has_action( 'manage_pages_custom_column' ) );
		$this->assertFalse( has_action( 'post_row_actions' ) );
		$this->assertFalse( has_action( 'page_row_actions' ) );
	}

	/**
	 * Test the add_filters_and_actions_for_screen() method doesn't add thumbnails or Share if screen not 'edit' base.
	 */
	public function test_add_filters_and_actions_for_screen_wrong_screen() {
		$post_list      = Post_List::get_instance();
		$current_screen = (object) array(
			'base'      => 'edit-tags',
			'post_type' => 'post',
		);
		$post_list->add_filters_and_actions_for_screen( $current_screen );

		$this->assertFalse( has_filter( 'manage_posts_columns' ) );
		$this->assertFalse( has_action( 'manage_posts_custom_column' ) );
		$this->assertFalse( has_filter( 'manage_pages_columns' ) );
		$this->assertFalse( has_action( 'manage_pages_custom_column' ) );
		$this->assertFalse( has_action( 'post_row_actions' ) );
		$this->assertFalse( has_action( 'page_row_actions' ) );
	}

	/**
	 * Test the add_thumbnail_column() method.
	 */
	public function test_add_thumbnail_column() {
		$columns = array(
			'cb'         => '<input type="checkbox" />',
			'title'      => 'Title',
			'author'     => 'Author',
			'categories' => 'Categories',
			'tags'       => 'Tags',
			'comments'   => '<span class="vers comment-grey-bubble" title="Comments"><span class="screen-reader-text">Comments</span></span>',
			'date'       => 'Date',
		);

		$columns_expected = array(
			'cb'         => '<input type="checkbox" />',
			'thumbnail'  => '<span>Thumbnail</span>',
			'title'      => 'Title',
			'author'     => 'Author',
			'categories' => 'Categories',
			'tags'       => 'Tags',
			'comments'   => '<span class="vers comment-grey-bubble" title="Comments"><span class="screen-reader-text">Comments</span></span>',
			'date'       => 'Date',
		);

		$post_list       = Post_List::get_instance();
		$columns_results = $post_list->add_thumbnail_column( $columns );

		$this->assertSame( $columns_results, $columns_expected );
	}

	/**
	 * Test the add_thumbnail_column() method with 'title' missing.
	 */
	public function test_add_thumbnail_column_no_title() {
		$columns = array(
			'cb'         => '<input type="checkbox" />',
			'author'     => 'Author',
			'categories' => 'Categories',
			'tags'       => 'Tags',
			'comments'   => '<span class="vers comment-grey-bubble" title="Comments"><span class="screen-reader-text">Comments</span></span>',
			'date'       => 'Date',
		);

		$post_list       = Post_List::get_instance();
		$columns_results = $post_list->add_thumbnail_column( $columns );

		$this->assertSame( $columns_results, $columns );
	}
}
