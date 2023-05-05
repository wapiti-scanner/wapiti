import { commentIcon, ellipsisIcon, followIcon, starIcon } from './icons';
import '../scss/action-bar.scss';

const actionBar = () => {
	return `
		<ul class="jetpack-action-bar__action-list">
			<li>
				<button class="jetpack-action-bar__action-button">
					${ ellipsisIcon() }
				</button>
			</li>
			<li>
				<button class="jetpack-action-bar__action-button">
					${ commentIcon() }
				</button>
			</li>
			<li>
				<button class="jetpack-action-bar__action-button">
					${ starIcon() }
				</button>
			</li>
			<li>
				<button class="jetpack-action-bar__action-button">
					${ followIcon() }
				</button>
			</li>
		</ul>`;
};
document.getElementById( 'jetpack-action-bar' ).innerHTML = actionBar();
