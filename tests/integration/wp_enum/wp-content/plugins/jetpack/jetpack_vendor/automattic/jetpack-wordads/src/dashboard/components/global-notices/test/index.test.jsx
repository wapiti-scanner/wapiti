/**
 * @jest-environment jsdom
 */

import { render } from '@testing-library/react';
import GlobalNotices from 'components/global-notices';
import React from 'react';

describe( 'GlobalNotices', function () {
	describe( 'rendering', function () {
		it( 'can render', () => {
			const { container } = render(
				<GlobalNotices notices={ [ { id: 1, status: 'success' } ] } />
			);
			// eslint-disable-next-line testing-library/no-node-access
			expect( container.firstChild ).toHaveClass( 'global-notices' );
		} );
	} );
} );
