<?php
/**
 * EU Cookie Law Widget form.
 *
 * @package automattic/jetpack
 */

use Automattic\Jetpack\Redirect;

// phpcs:disable VariableAnalysis.CodeAnalysis.VariableAnalysis.UndefinedVariable
?>
<p>
	<strong>
		<?php esc_html_e( 'Banner text', 'jetpack' ); ?>
	</strong>
	<ul>
		<li>
			<label>
				<input
					<?php checked( $instance['text'], 'default' ); ?>
					name="<?php echo esc_attr( $this->get_field_name( 'text' ) ); ?>"
					type="radio"
					value="default"
				/>
				<?php esc_html_e( 'Default', 'jetpack' ); ?>
			</label>
		</li>
		<li>
			<label>
				<input
					<?php checked( $instance['text'], 'custom' ); ?>
					name="<?php echo esc_attr( $this->get_field_name( 'text' ) ); ?>"
					type="radio"
					value="custom"
				/>
				<?php esc_html_e( 'Custom:', 'jetpack' ); ?>
			</label>
		</li>
	</ul>
	<textarea
		class="widefat"
		name="<?php echo esc_attr( $this->get_field_name( 'customtext' ) ); ?>"
		placeholder="<?php echo esc_attr( $instance['default-text'] ); ?>"
	><?php echo esc_html( $instance['customtext'] ); ?></textarea>
</p>

<hr />

<p>
	<strong>
		<?php esc_html_e( 'Privacy Policy Link', 'jetpack' ); ?>
	</strong>
	<ul class="eu-cookie-law-widget-policy-url">
		<li>
			<label>
				<input
					<?php checked( $instance['policy-url'], 'default' ); ?>
					name="<?php echo esc_attr( $this->get_field_name( 'policy-url' ) ); ?>"
					type="radio"
					value="default"
				/>
				<?php esc_html_e( 'Default', 'jetpack' ); ?>
			</label>
		</li>
		<li>
			<label>
				<input
					<?php checked( $instance['policy-url'], 'custom' ); ?>
					name="<?php echo esc_attr( $this->get_field_name( 'policy-url' ) ); ?>"
					type="radio"
					value="custom"
				/>
				<?php esc_html_e( 'Custom URL:', 'jetpack' ); ?>
			</label>
			<input
				class="widefat"
				name="<?php echo esc_attr( $this->get_field_name( 'custom-policy-url' ) ); ?>"
				placeholder="<?php echo esc_url( $instance['default-policy-url'] ); ?>"
				style="margin-top: .5em;"
				type="text"
				value="<?php echo esc_url( $instance['custom-policy-url'] ); ?>"
			/>
			<span class="notice notice-warning default-policy" style="display: none;">
				<span style="display: block; margin: .5em 0;">
					<strong><?php esc_html_e( 'Caution:', 'jetpack' ); ?></strong>
					<?php esc_html_e( 'The default policy URL only covers cookies set by Jetpack. If you’re running other plugins, custom cookies, or third-party tracking technologies, you should create and link to your own cookie statement.', 'jetpack' ); ?>
				</span>
			</span>
			<?php if ( Jetpack::is_module_active( 'wordads' ) ) : ?>
				<span class="notice notice-warning custom-policy" style="display: none;">
					<span style="display: block; margin: .5em 0;">
						<strong><?php esc_html_e( 'Caution:', 'jetpack' ); ?></strong>
						<?php
						echo sprintf(
							wp_kses(
								/* Translators: %s is the URL to a Jetpack support article. */
								__( 'For GDPR compliance, please make sure your policy contains <a href="%s" target="_blank">privacy information relating to WordAds</a>.', 'jetpack' ),
								array(
									'a' => array(
										'href'   => array(),
										'target' => array(),
									),
								)
							),
							esc_url( Redirect::get_url( 'jetpack-support-ads', array( 'anchor' => 'privacy' ) ) )
						);
						?>
					</span>
				</span>
			<?php endif; ?>
		</li>
	</ul>
</p>

<p>
	<strong>
		<?php esc_html_e( 'Link text', 'jetpack' ); ?>
	</strong>
	<label>
		<input
			class="widefat"
			name="<?php echo esc_attr( $this->get_field_name( 'policy-link-text' ) ); ?>"
			type="text"
			value="<?php echo esc_attr( $instance['policy-link-text'] ); ?>"
		/>
	</label>
</p>

<hr />

<p>
	<strong>
		<?php esc_html_e( 'Button text', 'jetpack' ); ?>
	</strong>
	<label>
		<input
			class="widefat"
			name="<?php echo esc_attr( $this->get_field_name( 'button' ) ); ?>"
			type="text"
			value="<?php echo esc_attr( $instance['button'] ); ?>"
		/>
	</label>
</p>

<hr />

<p>
	<strong>
		<?php esc_html_x( 'Capture consent & hide the banner', 'action', 'jetpack' ); ?>
	</strong>
	<ul>
		<li>
			<label>
				<input
					<?php checked( $instance['hide'], 'button' ); ?>
					name="<?php echo esc_attr( $this->get_field_name( 'hide' ) ); ?>"
					type="radio"
					value="button"
					<?php echo Jetpack::is_module_active( 'wordads' ) ? 'disabled' : ''; ?>
				/>
				<?php esc_html_e( 'after the user clicks the dismiss button', 'jetpack' ); ?>
			</label>
		</li>
		<li>
			<label>
				<input
					<?php checked( $instance['hide'], 'scroll' ); ?>
					name="<?php echo esc_attr( $this->get_field_name( 'hide' ) ); ?>"
					type="radio"
					value="scroll"
					<?php echo Jetpack::is_module_active( 'wordads' ) ? 'disabled' : ''; ?>
				/>
				<?php esc_html_e( 'after the user scrolls the page', 'jetpack' ); ?>
			</label>
		</li>
		<li>
			<label>
				<input
					<?php checked( $instance['hide'], 'time' ); ?>
					name="<?php echo esc_attr( $this->get_field_name( 'hide' ) ); ?>"
					type="radio"
					value="time"
					<?php echo Jetpack::is_module_active( 'wordads' ) ? 'disabled' : ''; ?>
				/>
				<?php esc_html_e( 'after this amount of time', 'jetpack' ); ?>
			</label>
			<input
				max="1000"
				min="3"
				name="<?php echo esc_attr( $this->get_field_name( 'hide-timeout' ) ); ?>"
				style="padding: 3px 5px; width: 3em;"
				type="number"
				value="<?php echo esc_attr( $instance['hide-timeout'] ); ?>"
			/>
			<?php esc_html_e( 'seconds', 'jetpack' ); ?>
		</li>
	</ul>
	<?php if ( Jetpack::is_module_active( 'wordads' ) ) : ?>
		<span class="notice notice-warning" style="display: block;">
			<span style="display: block; margin: .5em 0;">
				<?php esc_html_e( 'Visitors must provide consent by clicking the dismiss button when WordAds is turned on.', 'jetpack' ); ?>
			</span>
		</span>
	<?php endif; ?>
</p>

<hr />

<p>
	<strong>
		<?php esc_html_x( 'Consent expires after', 'action', 'jetpack' ); ?>
	</strong>
	<ul>
		<li>
			<input
				max="365"
				min="1"
				name="<?php echo esc_attr( $this->get_field_name( 'consent-expiration' ) ); ?>"
				style="padding: 3px 5px; width: 3.75em;"
				type="number"
				value="<?php echo esc_attr( $instance['consent-expiration'] ); ?>"
			/>
			<?php esc_html_e( 'days', 'jetpack' ); ?>
		</li>
	</ul>
</p>

<hr />

<p>
	<strong>
		<?php esc_html_e( 'Color scheme', 'jetpack' ); ?>
	</strong>
	<ul>
		<li>
			<label>
				<input
					<?php checked( $instance['color-scheme'], 'default' ); ?>
					name="<?php echo esc_attr( $this->get_field_name( 'color-scheme' ) ); ?>"
					type="radio"
					value="default"
				/>
				<?php esc_html_e( 'Light', 'jetpack' ); ?>
			</label>
		</li>
		<li>
			<label>
				<input
					<?php checked( $instance['color-scheme'], 'negative' ); ?>
					name="<?php echo esc_attr( $this->get_field_name( 'color-scheme' ) ); ?>"
					type="radio"
					value="negative"
				/>
				<?php esc_html_e( 'Dark', 'jetpack' ); ?>
			</label>
		</li>
	</ul>
</p>

<hr />

<p>
	<strong>
		<?php esc_html_e( 'Position', 'jetpack' ); ?>
	</strong>
	<ul>
		<li>
			<label>
				<input
					<?php checked( $instance['position'], 'bottom' ); ?>
					name="<?php echo esc_attr( $this->get_field_name( 'position' ) ); ?>"
					type="radio"
					value="bottom"
				/>
				<?php esc_html_e( 'Bottom', 'jetpack' ); ?>
			</label>
		</li>
		<li>
			<label>
				<input
					<?php checked( $instance['position'], 'top' ); ?>
					name="<?php echo esc_attr( $this->get_field_name( 'position' ) ); ?>"
					type="radio"
					value="top"
				/>
				<?php esc_html_e( 'Top', 'jetpack' ); ?>
			</label>
		</li>
	</ul>
</p>

<hr />

<p class="small">
	<?php esc_html_e( 'It is your own responsibility to ensure that your site complies with the relevant laws.', 'jetpack' ); ?>
	<a href="<?php echo esc_url( Redirect::get_url( 'jetpack-support-extra-sidebar-widgets-eu-cookie-law-widget' ) ); ?>">
		<?php esc_html_e( 'Click here for more information', 'jetpack' ); ?>
	</a>
</p>
