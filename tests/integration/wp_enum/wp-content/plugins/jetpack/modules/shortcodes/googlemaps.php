<?php
/**
 * Google Maps embeds.
 *
 * Supported formats:
 * <iframe width="425" height="350" frameborder="0" scrolling="no" marginheight="0" marginwidth="0" src="https://maps.google.com/maps?f=q&amp;source=s_q&amp;hl=bg&amp;geocode=&amp;q=%D0%9C%D0%BB%D0%B0%D0%B4%D0%BE%D1%81%D1%82+1,+%D0%A1%D0%BE%D1%84%D0%B8%D1%8F,+%D0%91%D1%8A%D0%BB%D0%B3%D0%B0%D1%80%D0%B8%D1%8F&amp;sll=37.0625,-95.677068&amp;sspn=40.545434,79.013672&amp;ie=UTF8&amp;hq=&amp;hnear=%D0%9C%D0%BB%D0%B0%D0%B4%D0%BE%D1%81%D1%82+1&amp;ll=42.654446,23.372061&amp;spn=0.036864,0.077162&amp;t=h&amp;z=14&amp;output=embed"></iframe><br /><small><a href="http://maps.google.com/maps?f=q&amp;source=embed&amp;hl=bg&amp;geocode=&amp;q=%D0%9C%D0%BB%D0%B0%D0%B4%D0%BE%D1%81%D1%82+1,+%D0%A1%D0%BE%D1%84%D0%B8%D1%8F,+%D0%91%D1%8A%D0%BB%D0%B3%D0%B0%D1%80%D0%B8%D1%8F&amp;sll=37.0625,-95.677068&amp;sspn=40.545434,79.013672&amp;ie=UTF8&amp;hq=&amp;hnear=%D0%9C%D0%BB%D0%B0%D0%B4%D0%BE%D1%81%D1%82+1&amp;ll=42.654446,23.372061&amp;spn=0.036864,0.077162&amp;t=h&amp;z=14" style="color:#0000FF;text-align:left">Вижте по-голяма карта</a></small>
 * [googlemaps https://maps.google.com/maps?f=q&hl=en&geocode=&q=San+Francisco,+CA&sll=43.469466,-83.998504&sspn=0.01115,0.025942&g=San+Francisco,+CA&ie=UTF8&z=12&iwloc=addr&ll=37.808156,-122.402458&output=embed&s=AARTsJp56EajYksz3JXgNCwT3LJnGsqqAQ&w=425&h=350]
 * [googlemaps https://mapsengine.google.com/map/embed?mid=zbBhkou4wwtE.kUmp8K6QJ7SA&w=640&h=480]
 *
 * @package automattic/jetpack
 */

/**
 * Google maps iframe - transforms code that looks like that:
 * <iframe width="425" height="350" frameborder="0" scrolling="no" marginheight="0" marginwidth="0" src="https://maps.google.com/maps?f=q&amp;source=s_q&amp;hl=bg&amp;geocode=&amp;q=%D0%9C%D0%BB%D0%B0%D0%B4%D0%BE%D1%81%D1%82+1,+%D0%A1%D0%BE%D1%84%D0%B8%D1%8F,+%D0%91%D1%8A%D0%BB%D0%B3%D0%B0%D1%80%D0%B8%D1%8F&amp;sll=37.0625,-95.677068&amp;sspn=40.545434,79.013672&amp;ie=UTF8&amp;hq=&amp;hnear=%D0%9C%D0%BB%D0%B0%D0%B4%D0%BE%D1%81%D1%82+1&amp;ll=42.654446,23.372061&amp;spn=0.036864,0.077162&amp;t=h&amp;z=14&amp;output=embed"></iframe><br /><small><a href="http://maps.google.com/maps?f=q&amp;source=embed&amp;hl=bg&amp;geocode=&amp;q=%D0%9C%D0%BB%D0%B0%D0%B4%D0%BE%D1%81%D1%82+1,+%D0%A1%D0%BE%D1%84%D0%B8%D1%8F,+%D0%91%D1%8A%D0%BB%D0%B3%D0%B0%D1%80%D0%B8%D1%8F&amp;sll=37.0625,-95.677068&amp;sspn=40.545434,79.013672&amp;ie=UTF8&amp;hq=&amp;hnear=%D0%9C%D0%BB%D0%B0%D0%B4%D0%BE%D1%81%D1%82+1&amp;ll=42.654446,23.372061&amp;spn=0.036864,0.077162&amp;t=h&amp;z=14" style="color:#0000FF;text-align:left">Вижте по-голяма карта</a></small>
 * into the [googlemaps http://...] shortcode format
 *
 * @param string $content Post content.
 */
function jetpack_googlemaps_embed_to_short_code( $content ) {

	if ( ! is_string( $content ) || ( false === strpos( $content, 'maps.google.' ) && 1 !== preg_match( '@google\.[^/]+/maps?@', $content ) ) ) {
		return $content;
	}

	/*
	 * IE and TinyMCE format things differently
	 * &lt;iframe width="425" height="350" frameborder="0" scrolling="no" marginheight="0" marginwidth="0" src="<a href="https://maps.google.co.uk/maps/ms?msa=0&amp;amp;msid=206216869547772496318.0004bf5f0ff25aea47bd9&amp;amp;hl=en&amp;amp;ie=UTF8&amp;amp;t=m&amp;amp;ll=50.91917,-1.398808&amp;amp;spn=0.013225,0.011794&amp;amp;output=embed&quot;&gt;&lt;/iframe&gt;&lt;br">https://maps.google.co.uk/maps/ms?msa=0&amp;amp;msid=206216869547772496318.0004bf5f0ff25aea47bd9&amp;amp;hl=en&amp;amp;ie=UTF8&amp;amp;t=m&amp;amp;ll=50.91917,-1.398808&amp;amp;spn=0.013225,0.011794&amp;amp;output=embed"&gt;&lt;/iframe&gt;&lt;br</a> /&gt;&lt;small&gt;View &lt;a href="<a href="https://maps.google.co.uk/maps/ms?msa=0&amp;amp;msid=206216869547772496318.0004bf5f0ff25aea47bd9&amp;amp;hl=en&amp;amp;ie=UTF8&amp;amp;t=m&amp;amp;ll=50.91917,-1.398808&amp;amp;spn=0.013225,0.011794&amp;amp;source=embed">https://maps.google.co.uk/maps/ms?msa=0&amp;amp;msid=206216869547772496318.0004bf5f0ff25aea47bd9&amp;amp;hl=en&amp;amp;ie=UTF8&amp;amp;t=m&amp;amp;ll=50.91917,-1.398808&amp;amp;spn=0.013225,0.011794&amp;amp;source=embed</a>" style="color:#0000FF;text-align:left"&gt;OARA Membership Discount Map&lt;/a&gt; in a larger map&lt;/small&gt;
	 */
	if ( strpos( $content, 'src="<a href="' ) !== false ) {
		$content = preg_replace_callback( '#&lt;iframe\s[^&]*?(?:&(?!gt;)[^&]*?)*?src="<a href="https?://(.*)?\.google\.(.*?)/(.*?)\?(.+?)&quot;[^&]*?(?:&(?!gt;)[^&]*?)*?&gt;\s*&lt;/iframe&gt;&lt;br">[^"]*?"&gt;\s*&lt;/iframe&gt;(?:&lt;br</a>\s*/&gt;\s*&lt;small&gt;.*?&lt;/small&gt;)?#i', 'jetpack_googlemaps_embed_to_short_code_callback', $content );
		return $content;
	}

	$content = preg_replace_callback( '!\<iframe\s[^>]*?src="https?://(.*)?\.google\.(.*?)/(.*?)\?(.+?)"[^>]*?\>\s*\</iframe\>(?:\s*(?:\<br\s*/?\>)?\s*\<small\>.*?\</small\>)?!i', 'jetpack_googlemaps_embed_to_short_code_callback', $content );

	$content = preg_replace_callback( '#&lt;iframe\s[^&]*?(?:&(?!gt;)[^&]*?)*?src="https?://(.*)?\.google\.(.*?)/(.*?)\?(.+?)"[^&]*?(?:&(?!gt;)[^&]*?)*?&gt;\s*&lt;/iframe&gt;(?:\s*(?:&lt;br\s*/?&gt;)?\s*&lt;small&gt;.*?&lt;/small&gt;)?#i', 'jetpack_googlemaps_embed_to_short_code_callback', $content );

	return $content;
}

/**
 * Callback transforming a Google Maps iFrame code into a shortcode.
 *
 * @param array $match Array of embed parameters used to build the final URL.
 */
function jetpack_googlemaps_embed_to_short_code_callback( $match ) {

	if ( preg_match( '/\bwidth=[\'"](\d+)(%)?/', $match[0], $width ) ) {
		$percent = ! empty( $width[2] ) ? '%' : '';
		$width   = absint( $width[1] ) . $percent;
	} else {
		$width = 425;
	}

	if ( preg_match( '/\bheight=[\'"](\d+)(%)?/', $match[0], $height ) ) {
		$percent = ! empty( $height[2] ) ? '%' : '';
		$height  = absint( $height[1] ) . $percent;
	} else {
		$height = 350;
	}

	$url = "https://{$match[1]}.google.{$match[2]}/{$match[3]}?{$match[4]}&amp;w={$width}&amp;h={$height}";

	/** This action is documented in modules/shortcodes/youtube.php */
	do_action( 'jetpack_embed_to_shortcode', 'googlemaps', $url );

	return "[googlemaps $url]";
}

add_filter( 'pre_kses', 'jetpack_googlemaps_embed_to_short_code' );

/**
 * Display the [googlemaps] shortcode
 *
 * @param array $atts Shortcode attributes.
 */
function jetpack_googlemaps_shortcode( $atts ) {
	if ( ! isset( $atts[0] ) ) {
		return '';
	}

	$params = ltrim( $atts[0], '=' );

	$width  = 425;
	$height = 350;

	if ( preg_match( '!^https?://(www|maps|mapsengine)\.google(\.co|\.com)?(\.[a-z]+)?/.*?(\?.+)!i', $params, $match ) ) {
		$params = str_replace( '&amp;amp;', '&amp;', $params );
		$params = str_replace( '&amp;', '&', $params );
		parse_str( $params, $arg );

		if ( isset( $arg['hq'] ) ) {
			unset( $arg['hq'] );
		}

		$url = '';
		foreach ( (array) $arg as $key => $value ) {
			if ( 'w' === $key ) {
				$percent = ( '%' === substr( $value, -1 ) ) ? '%' : '';
				$width   = (int) $value . $percent;
			} elseif ( 'h' === $key ) {
				$height = (int) $value;
			} else {
				$key  = str_replace( '_', '.', $key );
				$url .= esc_attr( "$key=$value&amp;" );
			}
		}
		$url = substr( $url, 0, -5 );

		$url = str_replace( 'http://', 'https://', $url );

		$css_class = 'googlemaps';

		if ( ! empty( $atts['align'] ) && in_array( strtolower( $atts['align'] ), array( 'left', 'center', 'right' ), true ) ) {
			$atts['align'] = strtolower( $atts['align'] );

			if ( 'left' === $atts['align'] ) {
				$css_class .= ' alignleft';
			} elseif ( 'center' === $atts['align'] ) {
				$css_class .= ' aligncenter';
			} elseif ( 'right' === $atts['align'] ) {
				$css_class .= ' alignright';
			}
		}

		$sandbox = class_exists( 'Jetpack_AMP_Support' ) && Jetpack_AMP_Support::is_amp_request()
			? 'sandbox="allow-popups allow-scripts allow-same-origin"'
			: '';

		return sprintf(
			'<div class="%1$s">
				<iframe width="%2$d" height="%3$d" frameborder="0" scrolling="no" marginheight="0" marginwidth="0" %5$s src="%4$s"></iframe>
			</div>',
			esc_attr( $css_class ),
			absint( $width ),
			absint( $height ),
			esc_url( $url ),
			$sandbox
		);
	}
}
add_shortcode( 'googlemaps', 'jetpack_googlemaps_shortcode' );
