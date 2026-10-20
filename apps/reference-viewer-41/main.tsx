import { useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { parseSnapshot, type ReferenceSnapshot } from './snapshot';
import synthetic from './synthetic-example.json';
import './style.css';

const unavailable = 'Unavailable: no evidenced game command';
function Disabled({ children }: { children: React.ReactNode }) {
  return <button disabled title={unavailable}>{children}</button>;
}

function App() {
  const [snapshot, setSnapshot] = useState<ReferenceSnapshot | null>(null);
  const [view, setView] = useState<'squad' | 'profile'>('squad');
  const [error, setError] = useState('');
  const request = useRef(0);
  function open(value: unknown) {
    setSnapshot(parseSnapshot(value));
    setView('squad');
    setError('');
  }
  async function load(file?: File) {
    if (!file) return;
    const sequence = ++request.current;
    setSnapshot(null);
    setView('squad');
    try {
      if (file.size > 128 * 1024) throw new Error('Snapshot exceeds 128 KiB limit');
      const value: unknown = JSON.parse(await file.text());
      if (sequence === request.current) open(value);
    } catch (error) {
      if (sequence === request.current) setError(error instanceof Error ? error.message : 'Invalid snapshot');
    }
  }
  const source = snapshot?.kind === 'captured-read-only' ? 'CAPTURED · READ ONLY' : 'SYNTHETIC EXAMPLE';
  return <div className="viewer">
    <aside className="sidebar">
      <div className="brand">REVERSAL<span>REFERENCE VIEW</span></div>
      <div className="date">{snapshot?.squad.dateLabel ?? '800 × 600'}</div>
      <Disabled>Continue Game</Disabled><Disabled>Competitions</Disabled><Disabled>Nations & Clubs</Disabled><Disabled>Find</Disabled><Disabled>Game Options</Disabled>
      <div className="sidebar-note">Game commands unavailable</div>
    </aside>
    <main>
      <header className="page-header"><span className="source-label">{snapshot ? source : 'CAPTURED REFERENCE VIEWER'}</span><h1>{snapshot ? (view === 'profile' ? snapshot.profile.title : snapshot.squad.clubLabel) : 'Squad → player profile'}</h1></header>
      <div className="load-bar"><label className="file-label">Load local JSON<input type="file" accept=".json,application/json" aria-label="Load local snapshot" onChange={event => { void load(event.target.files?.[0]); event.target.value = ''; }}/></label><button onClick={() => { ++request.current; open(synthetic); }}>Synthetic example</button><span>Local display only · no upload</span></div>
      {error && <p className="error" role="alert">{error}</p>}
      {!snapshot ? <section className="empty"><p className="eyebrow">OBSERVED NAVIGATION · CAPTURED VALUES</p><h2>Inspect a squad.<br/>Open its captured profile.</h2><p>Load a private R41 snapshot from this computer. Only a roster row with an accompanying captured profile can open.</p><p>The included example contains synthetic values. Tactics, transfers, time advancement and match commands are unavailable.</p></section> : <>
        <nav className="tabs" aria-label="Captured screen tabs">{(view === 'squad' ? ['Squad', 'Transfers', 'Next Match', 'Fixtures', 'Finances & Info'] : ['Profile', 'Injuries & Bans', 'Contract', 'Transfer', 'History']).map((label, index) => <button key={label} className={index === 0 ? 'active' : ''} disabled={index !== 0} aria-current={index === 0 ? 'page' : undefined} title={index !== 0 ? unavailable : 'Current captured view'}>{label}</button>)}</nav>
        <div className="capture-caption">{view === 'squad' ? snapshot.squad.captureId : snapshot.profile.captureId} · {view === 'squad' ? 'Captured order; only visible rows retained' : 'Captured attributes; other profile panels unavailable'}</div>
        {view === 'squad' ? <section className="squad" aria-label="Captured squad">
          <div className="squad-tools"><Disabled>View</Disabled><h2>Selection Info</h2><Disabled>Clear Squad</Disabled><Disabled>Filter</Disabled></div>
          <div className="table-wrap"><table><thead><tr>{['Pkd', 'Inf', 'Name', 'Position', 'Form', 'Morale', 'Cond.', 'Apps', 'Av R', 'Value'].map(label => <th key={label}>{label}</th>)}</tr></thead><tbody>{snapshot.squad.rows.map(row => <tr key={row.id}>
            <td className="picked">{row.picked}</td><td className="info">{row.info}</td><td className="player-name">{row.id === snapshot.profile.playerId ? <button className="player-link" onClick={() => setView('profile')}>{row.name}<span className="sr-only"> — open captured profile</span></button> : <span title="Profile not captured">{row.name}</span>}</td><td className="cyan">{row.position}</td><td>{row.form}</td><td>{row.morale}</td><td className="orange">{row.condition}</td><td className="cyan">{row.apps}</td><td className="cyan">{row.averageRating}</td><td className="value">{row.value}</td>
          </tr>)}</tbody></table></div>
          <div className="bottom-tabs"><Disabled>Tactics</Disabled><Disabled>Training</Disabled><Disabled>Last Match</Disabled><Disabled>League</Disabled><Disabled>History</Disabled></div>
        </section> : <section className="profile" aria-label="Captured player profile">
          <h2>{snapshot.profile.bio}</h2><div className="attribute-columns">{snapshot.profile.attributeColumns.map((column, index) => <dl key={index}>{column.map(attribute => <div key={attribute.label}><dt>{attribute.label}</dt><dd>{attribute.value}</dd></div>)}{index === 2 && [['Preferred Foot', snapshot.profile.preferredFoot], ['Form', snapshot.profile.form], ['Morale', snapshot.profile.morale], ['Condition', snapshot.profile.condition]].map(([label, value]) => <div key={label}><dt>{label}</dt><dd className="orange">{value}</dd></div>)}</dl>)}</div><p className="role">{snapshot.profile.role}</p><p className="omitted">Career statistics and other profiles are outside this captured view model.</p>
        </section>}
        <footer><button disabled={view === 'squad'} onClick={() => setView('squad')}>Back</button><Disabled>Next</Disabled></footer>
      </>}
    </main>
  </div>;
}

createRoot(document.getElementById('root')!).render(<App />);
