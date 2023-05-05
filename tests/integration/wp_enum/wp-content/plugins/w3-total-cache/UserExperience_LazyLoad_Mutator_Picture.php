<?php
namespace W3TC;

class UserExperience_LazyLoad_Mutator_Picture {
	private $common;



	public function __construct( $common ) {
		$this->common = $common;
	}



	public function run( $content ) {
		$content = preg_replace_callback(
			'~(<img\s[^>]+>)~i',
			array( $this, 'tag_img' ), $content
		);

		$content = preg_replace_callback(
			'~(<source\s[^>]+>)~i',
			array( $this, 'tag_source' ), $content
		);

		return $content;
	}



	public function tag_img( $matches ) {
		$content = $matches[0];

		// get image dimensions
		$dim = $this->common->tag_get_dimensions( $content );
		return $this->common->tag_img_content_replace( $content, $dim );
	}



	/**
	 * Common replace code for picture and img tags
	 */
	private function tag_source( $matches ) {
		$content = $matches[0];

		$content = preg_replace( '~(\s)(srcset|sizes)=~i',
			'$1data-$2=', $content );

		return $content;
	}
}
