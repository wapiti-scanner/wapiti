<?php
/**
 * Summary footer template.
 *
 * This template can be overridden by copying it to yourtheme/wpforms/emails/summary-footer.php.
 *
 * @since 1.6.2.3
 *
 * @version 1.6.2.3
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

?>

					</td>
				</tr>
				<tr>
					<td align="center" valign="top" class="footer">
						<?php
						echo wp_kses(
							sprintf( /* translators: %1$s - link to a site; %2$s - link to the documentation. */
								__( 'This email was auto-generated and sent from %1$s. Learn <a href="%2$s">how to disable</a>.', 'wpforms-lite' ),
								'<a href="' . esc_url( home_url() ) . '">' . esc_html( wp_specialchars_decode( get_bloginfo( 'name' ) ) ) . '</a>',
								'https://wpforms.com/docs/how-to-use-email-summaries/#faq'
							),
							[
								'a' => [
									'href' => [],
								],
							]
						);
						?>
					</td>
				</tr>
			</table>
		</td>
	</tr>
</table>
</body>
</html>
