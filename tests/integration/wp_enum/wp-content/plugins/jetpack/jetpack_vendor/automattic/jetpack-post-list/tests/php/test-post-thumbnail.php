<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * This file contains PHPUnit tests for the Post_Thumbnail class.
 * To run the package unit tests:
 * - go the post-list folder "cd projects/packages/post-list"
 * - run the command "composer test-php"
 *
 * @package automattic/jetpack-post-list
 */

namespace Automattic\Jetpack\Post_List;

use PHPUnit\Framework\TestCase;
/**
 * PHPUnit tests for the Post_Thumbnail class.
 *
 * @package automattic/jetpack-post-list
 */
class Test_Post_Thumbnail extends TestCase {

	/**
	 * Test that we get a null image attachment ID from invalid post content.
	 *
	 * @dataProvider invalid_post_content
	 *
	 * @param string $input The test post content to parse.
	 */
	public function test_get_first_image_id_from_invalid_post_content( $input ) {
		$attachment_id = Post_Thumbnail::get_first_image_id_from_post_content( $input );
		$this->assertNull( $attachment_id );
	}

	/**
	 * Data provider for invalid post content.
	 *
	 * @return array[]
	 */
	public function invalid_post_content() {
		return array(
			'Name does not exist.'                  => array( '.' ),
			'Name exists but outside of HTML.'      => array( 'wp-image-24' ),
			'Name exists but enclosed in a tag.'    => array( '<p>wp-image-24</p>' ),
			'Name exists but NOT in image tag.'     => array( '<div class="wp-image-24"></div>' ),
			'Name exists in img but NOT in class attribute.' => array( '<img id="wp-image-24"/>' ),
			'Name exists but number is missing.'    => array( '<img class="wp-image-" />' ),
			'Name exists but extra letters on end.' => array( '<img class="wp-image-24ab1" />' ),
			'Name exists but extra chars on front.' => array( '<img class="abcwp-image-24" />' ),
			'Name exists but inside (-) another.'   => array( '<img class="abc-wp-image-24-abc" />' ),
			'Name exists but inside (_) another.'   => array( '<img class="abc_wp-image-24_abc" />' ),
		);
	}

	/**
	 * Test that we get a valid image attachment ID from post content.
	 *
	 * @dataProvider valid_post_content
	 *
	 * @param int    $expected_result The expected image attachment ID.
	 * @param string $input The test post content to parse.
	 */
	public function test_get_first_image_id_from_valid_post_content( $expected_result, $input ) {
		$attachment_id = Post_Thumbnail::get_first_image_id_from_post_content( $input );
		$this->assertSame( $expected_result, $attachment_id );
	}

	/**
	 * Data provider for valid post content.
	 *
	 * @return array[]
	 */
	public function valid_post_content() {
		$post_content_gallery_image = '<!-- wp:paragraph -->
<p>Welcome to WordPress.</p>
<!-- /wp:paragraph -->

<!-- wp:gallery {"ids":[14],"linkTo":"none"} -->
<figure class="wp-block-gallery columns-1 is-cropped"><ul class="blocks-gallery-grid"><li class="blocks-gallery-item"><figure><img src="http://localhost/wp-content/uploads/2021/08/b311c1481829913164f33a353de10a66-1-1024x448.jpeg" alt="" data-id="14" data-full-url="http://localhost/wp-content/uploads/2021/08/b311c1481829913164f33a353de10a66-1.jpeg" data-link="http://localhost/2021/08/20/hello-world/b311c1481829913164f33a353de10a66-1/" class="wp-image-14"/></figure></li></ul></figure>
<!-- /wp:gallery -->';

		$post_content_slideshow_image = '<!-- wp:jetpack/slideshow {"ids":[18,5],"sizeSlug":"large"} -->
<div class="wp-block-jetpack-slideshow aligncenter" data-effect="slide"><div class="wp-block-jetpack-slideshow_container swiper-container"><ul class="wp-block-jetpack-slideshow_swiper-wrapper swiper-wrapper"><li class="wp-block-jetpack-slideshow_slide swiper-slide"><figure><img alt="" class="wp-block-jetpack-slideshow_image wp-image-18" data-id="18" src="http://localhost/wp-content/uploads/2021/08/b311c1481829913164f33a353de10a66-2-1024x448.jpeg"/></figure></li><li class="wp-block-jetpack-slideshow_slide swiper-slide"><figure><img alt="" class="wp-block-jetpack-slideshow_image wp-image-5" data-id="5" src="http://localhost/wp-content/uploads/2021/08/201D3C7E-1BAE-4896-81A5-C848E2FC2AD1-1024x768.jpeg"/></figure></li></ul><a class="wp-block-jetpack-slideshow_button-prev swiper-button-prev swiper-button-white" role="button"></a><a class="wp-block-jetpack-slideshow_button-next swiper-button-next swiper-button-white" role="button"></a><a aria-label="Pause Slideshow" class="wp-block-jetpack-slideshow_button-pause" role="button"></a><div class="wp-block-jetpack-slideshow_pagination swiper-pagination swiper-pagination-white"></div></div></div>
<!-- /wp:jetpack/slideshow -->';

		$post_content_image_block = '<!-- wp:image {"id":24,"sizeSlug":"large","linkDestination":"none"} -->
<figure class="wp-block-image size-large"><img src="http://localhost/wp-content/uploads/2021/08/b311c1481829913164f33a353de10a66-3-1024x448.jpeg" alt="" class="wp-image-24"/></figure>
<!-- /wp:image -->';

		return array(
			'Name is the only class value on the img tag.' => array( 24, '<img class="wp-image-24" />' ),
			'Name exists with extra spaces.'               => array( 24, '<img class=" wp-image-24 " />' ),
			'Name exists with single quotes.'              => array( 24, "<img class='wp-image-24' />" ),
			'Name found in the middle of class value.'     => array( 2, '<img class="front wp-image-2 end" />' ),
			'Name found on the end of class value.'        => array( 240, '<img class="front wp-image-240" />' ),
			'Name found on the front of class value.'      => array( 0, '<img class="wp-image-0 end" />' ),
			'ID in name is really long.'                   => array( 99999999999999, '<img class="wp-image-99999999999999" />' ),
			'Name found in example gallery post.'          => array( 14, $post_content_gallery_image ),
			'Name found in example slideshow post.'        => array( 18, $post_content_slideshow_image ),
			'Name found in example image block post.'      => array( 24, $post_content_image_block ),
		);
	}

	/**
	 * Test that when an ID is found, but we can't get the attachment details
	 * we still return null
	 */
	public function test_get_post_thumbnail_returns_null_when_attachment_unavailable() {
		$post               = new \stdClass();
		$post->ID           = 1;
		$post->post_content = '<!-- wp:image {"id":24,"sizeSlug":"large","linkDestination":"none"} -->
<figure class="wp-block-image size-large"><img src="http://localhost/wp-content/uploads/2021/08/b311c1481829913164f33a353de10a66-3-1024x448.jpeg" alt="" class="wp-image-24"/></figure>
<!-- /wp:image -->';
		$result             = Post_Thumbnail::get_post_thumbnail( $post );

		$this->assertNull( $result );
	}
}
