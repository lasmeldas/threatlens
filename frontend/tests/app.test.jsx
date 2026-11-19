import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import App from '../src/App.jsx';
import { tokenStore } from '../src/api.js';
import { alertFixture, mockApi, renderApp } from './helpers.jsx';

const stats = { alerts: 3, open: 2, uploads: 1, by_severity: { critical: 1, high: 1, medium: 1 }, by_status: { new: 2, resolved: 1 }, by_kind: { brute_force: 1 }, top_ips: [{ ip: '203.0.113.45', alerts: 2 }] };
const page = (results) => ({ count: results.length, next: null, previous: null, results });

describe('sign in', () => {
  it('shows the sign-in form first and reports a wrong password', async () => {
    mockApi({ 'POST /api/auth/token/': { status: 400, body: { non_field_errors: ['Unable to log in with provided credentials.'] } } });
    renderApp(<App />);
    await userEvent.type(screen.getByLabelText('Username'), 'ana');
    await userEvent.type(screen.getByLabelText('Password'), 'wrong');
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Unable to log in');
    expect(tokenStore.get()).toBeNull();
  });

  it('signs in, stores the token for this tab and shows the overview', async () => {
    mockApi({ 'POST /api/auth/token/': { body: { token: 't1', user: { username: 'ana', role: 'analyst' } } }, 'GET /api/stats/': { body: stats } });
    renderApp(<App />);
    await userEvent.type(screen.getByLabelText('Username'), 'ana');
    await userEvent.type(screen.getByLabelText('Password'), 'correct-horse-battery-1');
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(await screen.findByRole('heading', { name: 'Overview' })).toBeInTheDocument();
    expect(tokenStore.get()).toBe('t1');
    expect(screen.getByText('analyst')).toBeInTheDocument();
  });

  it('restores a session from a stored token, and returns to sign-in when it is rejected', async () => {
    tokenStore.set('stale');
    mockApi({ 'GET /api/me/': { status: 401, body: { detail: 'This token has expired. Sign in again.' } } });
    renderApp(<App />);
    expect(await screen.findByRole('button', { name: 'Sign in' })).toBeInTheDocument();
    expect(tokenStore.get()).toBeNull();
  });

  it('signing out revokes the token', async () => {
    tokenStore.set('t1');
    const calls = mockApi({ 'GET /api/me/': { body: { username: 'ana', role: 'analyst' } }, 'GET /api/stats/': { body: stats }, 'POST /api/auth/logout/': { status: 204 } });
    renderApp(<App />);
    await userEvent.click(await screen.findByRole('button', { name: 'Sign out' }));
    expect(await screen.findByRole('button', { name: 'Sign in' })).toBeInTheDocument();
    expect(calls.some((c) => c.key === 'POST /api/auth/logout/')).toBe(true);
    expect(tokenStore.get()).toBeNull();
  });
});

describe('overview', () => {
  it('shows totals and charts, and hides uploading from viewers', async () => {
    tokenStore.set('t');
    mockApi({ 'GET /api/me/': { body: { username: 'vic', role: 'viewer' } }, 'GET /api/stats/': { body: stats } });
    renderApp(<App />);
    const totals = await screen.findByRole('region', { name: 'Totals' });
    expect(within(totals).getByText('3')).toBeInTheDocument();
    expect(screen.getByText('By severity')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: '203.0.113.45' })).toHaveAttribute('href', '/alerts?ip=203.0.113.45');
    expect(screen.queryByRole('form', { name: 'Analyse data' })).not.toBeInTheDocument();
    expect(screen.getByText(/read-only/)).toBeInTheDocument();
  });

  it('lets an analyst upload a log and refreshes the totals', async () => {
    tokenStore.set('t');
    let loads = 0;
    const calls = mockApi({
      'GET /api/me/': { body: { username: 'ana', role: 'analyst' } },
      'GET /api/stats/': () => { loads += 1; return { body: stats }; },
      'POST /api/uploads/': { status: 201, body: { id: 2, events: 6, failed: 5, alert_count: 1 } },
    });
    renderApp(<App />);
    await userEvent.type(await screen.findByLabelText('Paste log lines'), 'Nov  8 03:12:01 web01 sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2');
    await userEvent.click(screen.getByRole('button', { name: 'Analyse' }));
    expect(await screen.findByRole('status')).toHaveTextContent('Analysed 6 login events (5 failed): 1 alert raised.');
    expect(loads).toBe(2);
    expect(calls.find((c) => c.key === 'POST /api/uploads/').body.get('threshold')).toBe('5');
  });
});

describe('alerts list', () => {
  it('sends the chosen filters to the API and lists the results', async () => {
    tokenStore.set('t');
    const calls = mockApi({
      'GET /api/me/': { body: { username: 'ana', role: 'analyst' } },
      'GET /api/alerts/': (init, u) => ({ body: page(u.searchParams.get('severity') === 'critical' ? [alertFixture()] : [alertFixture(), alertFixture({ id: 2, severity: 'high', kind: 'brute_force' })]) }),
    });
    renderApp(<App />, { path: '/alerts' });
    expect(await screen.findAllByRole('row')).toHaveLength(3);
    await userEvent.selectOptions(screen.getByLabelText('Severity'), 'critical');
    await waitFor(() => expect(screen.getAllByRole('row')).toHaveLength(2));
    expect(calls.at(-1).search).toBe('?severity=critical');
    expect(screen.getByText('203.0.113.45')).toBeInTheDocument();
  });

  it('starts from the address in the URL and says when nothing matches', async () => {
    tokenStore.set('t');
    const calls = mockApi({ 'GET /api/me/': { body: { username: 'ana', role: 'analyst' } }, 'GET /api/alerts/': { body: page([]) } });
    renderApp(<App />, { path: '/alerts?ip=9.9.9.9' });
    expect(await screen.findByText('No alerts match these filters.')).toBeInTheDocument();
    expect(calls.at(-1).search).toBe('?ip=9.9.9.9');
  });

  it('pages through results', async () => {
    tokenStore.set('t');
    const calls = mockApi({ 'GET /api/me/': { body: { username: 'ana', role: 'analyst' } }, 'GET /api/alerts/': { body: { count: 40, next: 'x', previous: null, results: [alertFixture()] } } });
    renderApp(<App />, { path: '/alerts' });
    await userEvent.click(await screen.findByRole('button', { name: 'Next' }));
    await waitFor(() => expect(calls.at(-1).search).toBe('?page=2'));
  });
});

describe('alert detail', () => {
  const routes = (role, patch) => ({ 'GET /api/me/': { body: { username: 'u', role } }, 'GET /api/alerts/1/': { body: alertFixture() }, ...(patch ? { 'PATCH /api/alerts/1/': patch } : {}) });

  it('lets an analyst change the status', async () => {
    tokenStore.set('t');
    const calls = mockApi(routes('analyst', (init) => ({ body: alertFixture({ status: JSON.parse(init.body).status }) })));
    renderApp(<App />, { path: '/alerts/1' });
    await userEvent.click(await screen.findByRole('button', { name: 'Investigating' }));
    await waitFor(() => expect(screen.getByTestId('status')).toHaveTextContent('Investigating'));
    expect(JSON.parse(calls.find((c) => c.key === 'PATCH /api/alerts/1/').body)).toEqual({ status: 'investigating' });
  });

  it('gives viewers no way to change it', async () => {
    tokenStore.set('t');
    mockApi(routes('viewer'));
    renderApp(<App />, { path: '/alerts/1' });
    expect(await screen.findByText(/succeeded after 7 failures/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Resolved' })).not.toBeInTheDocument();
    expect(screen.getByText(/read-only/)).toBeInTheDocument();
  });

  it('shows the server error when the change is refused', async () => {
    tokenStore.set('t');
    mockApi(routes('analyst', { status: 403, body: { detail: 'You do not have permission to perform this action.' } }));
    renderApp(<App />, { path: '/alerts/1' });
    await userEvent.click(await screen.findByRole('button', { name: 'Resolved' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('do not have permission');
    expect(screen.getByTestId('status')).toHaveTextContent('New');
  });
});

describe('machine-learning features', () => {
  const analyst = { 'GET /api/me/': { body: { username: 'ana', role: 'analyst' } }, 'GET /api/stats/': { body: stats } };

  it('scores connection records and reports the result', async () => {
    tokenStore.set('t');
    const calls = mockApi({
      ...analyst,
      'POST /api/connections/': { status: 201, body: { records: 60, flagged: 14, alerts_created: 14, against_labels: { records: 60, agreed: 44, attacks_missed: 16, false_alarms: 0 } } },
    });
    renderApp(<App />);
    await userEvent.click(await screen.findByRole('tab', { name: /Network connections/ }));
    await userEvent.type(screen.getByLabelText(/Paste connection records/), '0,tcp,http');
    await userEvent.click(screen.getByRole('button', { name: 'Analyse' }));
    const status = await screen.findByRole('status');
    expect(status).toHaveTextContent('Scored 60 connection records: 14 flagged as likely attacks, 14 alerts raised.');
    expect(status).toHaveTextContent('44 of 60 agree, 16 attacks missed, 0 false alarms');
    const sent = calls.find((c) => c.key === 'POST /api/connections/').body;
    expect(sent.get('csv')).toBe('0,tcp,http');
    expect(sent.get('threshold')).toBe('0.5');
  });

  it('shows the server message when records are malformed', async () => {
    tokenStore.set('t');
    mockApi({ ...analyst, 'POST /api/connections/': { status: 400, body: { detail: 'Each record needs 41 values (or 43 with the label and difficulty columns at the end); found 3.' } } });
    renderApp(<App />);
    await userEvent.click(await screen.findByRole('tab', { name: /Network connections/ }));
    await userEvent.type(screen.getByLabelText(/Paste connection records/), '1,2,3');
    await userEvent.click(screen.getByRole('button', { name: 'Analyse' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('41 values');
  });

  it('lists ML alerts with their score instead of an address', async () => {
    tokenStore.set('t');
    mockApi({ 'GET /api/me/': { body: { username: 'ana', role: 'analyst' } }, 'GET /api/alerts/': { body: page([alertFixture({ id: 9, severity: 'high', kind: 'network_attack', source: 'ml', score: 0.97, ip: '', failures: 0, users: [] })]) } });
    renderApp(<App />, { path: '/alerts' });
    expect(await screen.findByText('97% attack chance')).toBeInTheDocument();
    expect(screen.getByText('network attack (ML)')).toBeInTheDocument();
    expect(screen.getByText('n/a')).toBeInTheDocument();
  });

  it('shows the score and the model note on an ML alert, with no address facts', async () => {
    tokenStore.set('t');
    mockApi({ 'GET /api/me/': { body: { username: 'ana', role: 'analyst' } }, 'GET /api/alerts/9/': { body: alertFixture({ id: 9, severity: 'high', kind: 'network_attack', source: 'ml', score: 0.97, ip: '', failures: 0, users: [], detail: 'Record 3: the model gives a 97% chance this is an attack.' }) } });
    renderApp(<App />, { path: '/alerts/9' });
    expect(await screen.findByTestId('score')).toHaveTextContent('97%');
    expect(screen.queryByText('Usernames tried')).not.toBeInTheDocument();
  });

  it('shows the model page with the weak spots, not just the headline', async () => {
    tokenStore.set('t');
    mockApi({
      'GET /api/me/': { body: { username: 'vic', role: 'viewer' } },
      'GET /api/ml/model/': { body: {
        dataset: 'NSL-KDD', selected_model: 'gradient_boosting', train_records: 125973, test_records: 22544,
        test: { accuracy: 0.8032, precision: 0.9693, recall: 0.6757, false_positive_rate: 0.0283 },
        compared_on_test: { gradient_boosting: { accuracy: 0.8032, precision: 0.9693, recall: 0.6757, false_positive_rate: 0.0283 }, logistic_regression: { accuracy: 0.7539, precision: 0.9177, recall: 0.6236, false_positive_rate: 0.0739 } },
        by_category: { normal: { correctly_classified: 0.9717 }, R2L: { correctly_classified: 0.1061 } },
        unseen_attacks: { records_of_unseen_types: 3750, detected_unseen: 0.4061, detected_seen: 0.787 },
      } },
    });
    renderApp(<App />, { path: '/model' });
    const results = await screen.findByRole('region', { name: 'Test results' });
    expect(within(results).getByText('80.3%')).toBeInTheDocument();
    expect(within(results).getByText('67.6%')).toBeInTheDocument();
    expect(screen.getByText('40.6%')).toBeInTheDocument();
    expect(screen.getByTestId('bar-R2L (e.g. password guessing)')).toHaveStyle({ width: '11%' });
    expect(screen.getByText(/misses about a third of attacks/)).toBeInTheDocument();
    expect(screen.getByText('Gradient boosting (used here)')).toBeInTheDocument();
  });
});
