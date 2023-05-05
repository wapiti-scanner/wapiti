<?php
/**
 * Jetpack_Flickr_Widget settings form output.
 *
 * @package automattic/jetpack
 */

//phpcs:disable VariableAnalysis.CodeAnalysis.VariableAnalysis.UndefinedVariable
?>
<p>
	<label>
		<?php esc_html_e( 'Title:', 'jetpack' ); ?>
	</label>
	<input
		class="widefat"
		name="<?php echo esc_attr( $this->get_field_name( 'title' ) ); ?>"
		type="text"
		value="<?php echo esc_attr( $instance['title'] ); ?>"
	/>
</p>

<p>
	<label>
		<?php esc_html_e( 'Flickr RSS URL:', 'jetpack' ); ?>
	</label>
	<input
		class="widefat"
		name="<?php echo esc_attr( $this->get_field_name( 'flickr_rss_url' ) ); ?>"
		type="text"
		value="<?php echo esc_attr( $instance['flickr_rss_url'] ); ?>"
	/>
</p>
<p>
	<small>
		<?php esc_html_e( 'To find your Flickr RSS URL, go to your photostream, add "?details=1" to the URL, and hit enter. Scroll down until you see the RSS icon or the "Latest" link. Right-click on either options and copy the URL. Paste into the box above.', 'jetpack' ); ?>
	</small>
</p>
<p>
	<small>
		<?php
		echo sprintf(
			wp_kses(
				/* Translators: %s is the URL to an example Flickr RSS feed. */
				__( 'Leave the Flickr RSS URL field blank to display <a target="_blank" href="%s">interesting</a> Flickr photos.', 'jetpack' ),
				array(
					'a' => array(
						'href'   => array(),
						'target' => array(),
					),
				)
			),
			'https://www.flickr.com/explore/interesting'
		);
		?>
	</small>
</p>

<p>
	<label>
		<?php esc_html_e( 'How many photos would you like to display?', 'jetpack' ); ?>
	</label>
	<select name="<?php echo esc_attr( $this->get_field_name( 'items' ) ); ?>">
		<?php for ( $i = 1; $i <= 10; ++$i ) { ?>
			<option
				<?php selected( $instance['items'], $i ); ?>
				value="<?php echo esc_attr( $i ); ?>"
			>
				<?php echo esc_html( $i ); ?>
			</option>
		<?php } ?>
	</select>
</p>

<p>
	<label>
		<input
			type="checkbox"
			name="<?php echo esc_attr( $this->get_field_name( 'target' ) ); ?>"
			<?php checked( $instance['target'] ); ?>
		/>
		<?php esc_html_e( 'Open images in new tab?', 'jetpack' ); ?>
	</label>
</p>
<p>
	<div>
		<?php esc_html_e( 'What size photos would you like to display?', 'jetpack' ); ?>
	</div>
	<ul>
		<li>
			<label>
				<input
					<?php checked( $instance['flickr_image_size'], 'thumbnail' ); ?>
					name="<?php echo esc_attr( $this->get_field_name( 'flickr_image_size' ) ); ?>"
					type="radio"
					value="thumbnail"
				/>
				<?php esc_html_e( 'Thumbnail', 'jetpack' ); ?>
			</label>
		</li>
		<li>
			<label>
				<input
					<?php checked( $instance['flickr_image_size'], 'small' ); ?>
					name="<?php echo esc_attr( $this->get_field_name( 'flickr_image_size' ) ); ?>"
					type="radio"
					value="small"
				/>
				<?php esc_html_e( 'Medium', 'jetpack' ); ?>
			</label>
		</li>
		<li>
			<label>
				<input
					<?php checked( $instance['flickr_image_size'], 'large' ); ?>
					name="<?php echo esc_attr( $this->get_field_name( 'flickr_image_size' ) ); ?>"
					type="radio"
					value="large"
				/>
				<?php esc_html_e( 'Large', 'jetpack' ); ?>
			</label>
		</li>
	</ul>
</p>
