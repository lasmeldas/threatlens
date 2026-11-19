import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import BarChart from '../src/components/BarChart.jsx';

describe('BarChart', () => {
  it('scales bars to the largest value', () => {
    render(<BarChart title="By severity" data={[{ label: 'critical', value: 4 }, { label: 'high', value: 2 }, { label: 'medium', value: 0 }]} />);
    expect(screen.getByTestId('bar-critical')).toHaveStyle({ width: '100%' });
    expect(screen.getByTestId('bar-high')).toHaveStyle({ width: '50%' });
    expect(screen.getByTestId('bar-medium')).toHaveStyle({ width: '0%' });
  });

  it('can scale to a fixed maximum such as 100 percent', () => {
    render(<BarChart title="Percent" scaleMax={100} data={[{ label: 'a', value: 40 }, { label: 'b', value: 10 }]} />);
    expect(screen.getByTestId('bar-a')).toHaveStyle({ width: '40%' });
    expect(screen.getByTestId('bar-b')).toHaveStyle({ width: '10%' });
  });

  it('says so when there is nothing to draw', () => {
    render(<BarChart title="By status" data={[]} empty="Nothing here." />);
    expect(screen.getByText('Nothing here.')).toBeInTheDocument();
  });
});
