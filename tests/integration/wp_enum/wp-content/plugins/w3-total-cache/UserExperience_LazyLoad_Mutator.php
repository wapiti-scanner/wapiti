<?php
namespace W3TC;

class UserExperience_LazyLoad_Mutator {
	private $config;
	private $modified = false;
	private $excludes;
	private $posts_by_url;



	public function __construct( $config, $posts_by_url ) {
		$this->config = $config;
		$this->posts_by_url = $posts_by_url;
	}



	public function run( $buffer ) {
		$this->excludes = apply_filters( 'w3tc_lazyload_excludes',
			$this->config->get_array( 'lazyload.exclude' ) );

		$r = apply_filters( 'w3tc_lazyload_mutator_before', array(
			'buffer' => $buffer,
			'modified' => $this->modified
		) );
		$buffer = $r['buffer'];
		$this->modified = $r['modified'];

		$unmutable = new UserExperience_LazyLoad_Mutator_Unmutable();
		$buffer = $unmutable->remove_unmutable( $buffer );

		if ( $this->config->get_boolean( 'lazyload.process_img' ) ) {
			$buffer = preg_replace_callback(
				'~<picture(\s[^>]+)*>(.*?)</picture>~is',
				array( $this, 'tag_picture' ), $buffer
			);
			$buffer = preg_replace_callback(
				'~<img\s[^>]+>~is',
				array( $this, 'tag_img' ), $buffer
			);
		}

		if ( $this->config->get_boolean( 'lazyload.process_background' ) ) {
			$buffer = preg_replace_callback(
				'~<[^>]+background(-image)?:\s*url[^>]+>~is',
				array( $this, 'tag_with_background' ), $buffer
			);
		}

		$buffer = $unmutable->restore_unmutable( $buffer );

		return $buffer;
	}



	public function content_modified() {
		return $this->modified;
	}



	public function tag_picture( $matches ) {
		$content = $matches[0];

		if ( $this->is_content_excluded( $content ) ) {
			return $content;
		}

		$m = new UserExperience_LazyLoad_Mutator_Picture( $this );
		return $m->run( $content );
	}



	public function tag_img( $matches ) {
		$content = $matches[0];

		if ( $this->is_content_excluded( $content ) ) {
			return $content;
		}

		// get image dimensions
		$dim = $this->tag_get_dimensions( $content );
		return $this->tag_img_content_replace( $content, $dim );
	}



	/**
	 * Common replace code for picture and img tags
	 */
	public function tag_img_content_replace( $content, $dim ) {
		// do replace
		$count = 0;
		$content = preg_replace( '~(\s)src=~is',
			'$1src="' . $this->placeholder( $dim['w'], $dim['h'] ) .
			'" data-src=', $content, -1, $count );

		if ( $count > 0 ) {
			$content = preg_replace( '~(\s)(srcset|sizes)=~is',
				'$1data-$2=', $content );

			$content = $this->add_class_lazy( $content );
			$content = $this->remove_native_lazy( $content );
			$this->modified = true;
		}

		return $content;
	}



	/**
	 * Common get dimensions of image
	 */
	public function tag_get_dimensions( $content ) {
		$dim = array( 'w' => 1, 'h' => 1 );
		$m = null;
		if ( preg_match( '~\swidth=[\s\'"]*([0-9]+)~is', $content, $m ) ) {
			$dim['h'] = $dim['w'] = (int)$m[1];

			if ( preg_match( '~\sheight=[\s\'"]*([0-9]+)~is', $content, $m ) ) {
				$dim['h'] = (int)$m[1];
				return $dim;
			}
		}

		// if not in attributes - try to find via url
		if ( !preg_match( '~\ssrc=(\'([^\']*)\'|"([^"]*)"|([^\'"][^\\s]*))~is',
				$content, $m ) ) {
			return $dim;
		}

		$url = ( !empty( $m[4] ) ? $m[4] : ( ( !empty( $m[3] ) ? $m[3] : $m[2] ) ) );

		// full url found
		if ( isset( $this->posts_by_url[$url] ) ) {
			$post_id = $this->posts_by_url[$url];

			$image = wp_get_attachment_image_src( $post_id, 'full' );
			if ( $image ) {
				$dim['w'] = $image[1];
				$dim['h'] = $image[2];
			}

			return $dim;
		}

		// try resized url by format
		static $base_url = null;
		if ( is_null( $base_url ) ) {
			$base_url = wp_get_upload_dir()['baseurl'];
		}

		if ( substr( $url, 0, strlen( $base_url ) ) == $base_url &&
				 preg_match( '~(.+)-(\\d+)x(\\d+)(\\.[a-z0-9]+)$~is', $url, $m ) ) {
			$dim['w'] = (int)$m[2];
			$dim['h'] = (int)$m[3];
		}

		return $dim;
	}



	public function tag_with_background( $matches ) {
		$content = $matches[0];

		if ( $this->is_content_excluded( $content ) ) {
			return $content;
		}

		$quote_match = null;
		if ( !preg_match( '~\s+style\s*=\s*([\"\'])~is', $content, $quote_match ) ) {
			return $content;
		}
		$quote = $quote_match[1];

		$count = 0;
		$content = preg_replace_callback(
			'~(\s+)(style\s*=\s*[' . $quote . '])(.*?)([' . $quote . '])~is',
			array( $this, 'style_offload_background' ), $content, -1, $count
		);

		if ( $count > 0 ) {
			$content = $this->add_class_lazy( $content );
			$this->modified = true;
		}

		return $content;
	}



	public function style_offload_background( $matches ) {
		list( $match, $v1, $v2, $v, $quote ) = $matches;
		$url_match = null;
		preg_match( '~background(-image)?:\s*(url\([^>]+\))~is', $v, $url_match );
		$v = preg_replace( '~background(-image)?:\s*url\([^>]+\)[;]?\s*~is', '', $v );

		return $v1 . $v2 . $v . $quote . ' data-bg=' . $quote . $url_match[2] . $quote;
	}



	private function add_class_lazy( $content ) {
		$count = 0;
		$content = preg_replace_callback(
			'~(\s+)(class=)([\"\'])(.*?)([\"\'])~is',
			array( $this, 'class_process' ), $content, -1, $count
		);

		if ( $count <= 0) {
			$content = preg_replace(
				'~<(\S+)(\s+)~is', '<$1$2class="lazy" ', $content
			);
		}

		return $content;
	}



	/**
	 * In safari javascript lazy-loaded image with loading="lazy"
	 * dont fire events, i.e. image not loaded
	 */
	public function remove_native_lazy( $content ) {
		return preg_replace(
			'~(\s+)loading=[\'"]lazy[\'"]~is', '', $content
		);
	}



	public function class_process( $matches ) {
		list( $match, $v1, $v2, $quote, $v ) = $matches;
		if ( preg_match( '~(^|\\s)lazy(\\s|$)~is', $v ) ) {
			return $match;
		}

		$v .= ' lazy';

		return $v1 . $v2 . $quote . $v . $quote;
	}



	private function is_content_excluded( $content ) {
		foreach ( $this->excludes as $w ) {
			if ( !empty($w) ) {
				if ( strpos( $content, $w ) !== FALSE ) {
					return true;
				}
			}
		}

		return false;
	}



	public function placeholder( $w, $h ) {
		return 'data:image/svg+xml,%3Csvg%20xmlns=\'http://www.w3.org/2000/svg\'%20viewBox=\'0%200%20' .
			$w . '%20'. $h . '\'%3E%3C/svg%3E';
	}
}
