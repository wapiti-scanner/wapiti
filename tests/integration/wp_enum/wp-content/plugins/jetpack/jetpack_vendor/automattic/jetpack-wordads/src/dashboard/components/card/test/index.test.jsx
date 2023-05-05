/**
 * @jest-environment jsdom
 */

import { render, screen } from '@testing-library/react';
import Card from 'components/card';
import React from 'react';

describe( 'Card', function () {
	it( 'can render', () => {
		render( <Card title="Title" /> );
		expect( screen.getByRole( 'heading' ) ).toBeInTheDocument();
	} );
} );
