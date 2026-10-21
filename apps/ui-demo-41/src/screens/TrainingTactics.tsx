import { useState } from 'react';
import { demoData } from '../data';
import type { Club, Player } from '../types';
import './TrainingTactics.css';

interface CommonProps {
  club: Club;
  onClose: () => void;
  show: (label: string) => void;
}

const trainingTabs = ['Overview', 'No Training (0)', 'General', 'Fitness (0)', 'Shooting (0)'];
const attributeGroups = ['Physical', 'Mental', 'Goalkeeping', 'Defensive', 'Attacking'];
const groupLabels: Record<string, string[]> = {
  Physical: ['Acceleration', 'Agility', 'Balance', 'Jumping', 'Pace', 'Stamina', 'Strength'],
  Mental: ['Aggression', 'Anticipation', 'Bravery', 'Decisions', 'Determination', 'Influence', 'Teamwork'],
  Goalkeeping: ['Handling', 'Reflexes', 'Positioning', 'Decisions', 'Agility', 'Jumping', 'Bravery'],
  Defensive: ['Marking', 'Tackling', 'Positioning', 'Heading', 'Strength', 'Teamwork', 'Work Rate'],
  Attacking: ['Crossing', 'Dribbling', 'Finishing', 'Long Shots', 'Off The Ball', 'Passing', 'Technique'],
};

function clubPlayers(clubId: string) {
  return Object.values(demoData.players).filter(player => player.clubId === clubId);
}

export function TrainingScreen({ club, onClose, show }: CommonProps) {
  const players = clubPlayers(club.id);
  const [tab, setTab] = useState('Overview');
  const [view, setView] = useState('Summary');
  const [category, setCategory] = useState('Physical');
  const [menu, setMenu] = useState<'view' | 'category' | null>(null);
  const visiblePlayers = tab.startsWith('No Training') || tab.startsWith('Fitness') || tab.startsWith('Shooting') ? [] : players;
  const labels = groupLabels[category];
  function cancel() {
    if (menu) setMenu(null);
    else onClose();
  }
  return <section className="training-screen">
    <nav className="tabs" aria-label="Training tabs">{trainingTabs.map(label => <button key={label} className={tab === label ? 'active' : ''} onClick={() => { setTab(label); setMenu(null); }}>{label === 'General' ? `General (${players.length})` : label}</button>)}</nav>
    <div className="training-tools">
      <button onClick={() => show('Training Schedule')}>Schedule ▾</button>
      <button onClick={() => setMenu(menu === 'view' ? null : 'view')}>View ▾</button>
      {view === 'Attributes' && <button onClick={() => setMenu(menu === 'category' ? null : 'category')}>{category} ▾</button>}
      <span />
      <button onClick={() => show(tab === 'Overview' ? 'Coaches' : 'Training Edit')}>{tab === 'Overview' ? 'Coaches' : 'Edit'} ▾</button>
      <button onClick={() => show('Training Filter')}>Filter ▾</button>
    </div>
    {menu === 'view' && <div className="training-popup view" role="menu" aria-label="Training View"><button role="menuitem" onClick={() => { setView('Summary'); setMenu(null); }}>Summary</button><button role="menuitem" onClick={() => { setView('Attributes'); setMenu('category'); }}>Attributes</button></div>}
    {menu === 'category' && <div className="training-popup category" role="menu" aria-label="Training attribute categories">{attributeGroups.map(label => <button key={label} role="menuitem" onClick={() => { setCategory(label); setMenu(null); }}>{category === label ? '✓ ' : ''}{label}</button>)}</div>}
    <div className="training-body">
      {visiblePlayers.length > 0 && <div className="training-scroll"><table><thead><tr>{[view === 'Summary' ? 'Schedule' : 'Schedule', 'Inf', 'Name', 'Position', ...(view === 'Summary' ? ['Age','Form','Morale','Cond.'] : labels.map(label => label.slice(0,3))), 'Value'].map((label,index) => <th key={`${label}-${index}`}>{label}</th>)}</tr></thead><tbody>{visiblePlayers.map(player => <TrainingRow key={player.id} player={player} view={view} labels={labels} />)}</tbody></table></div>}
    </div>
    <div className="training-groups">{['Skill (0)','Tactics (0)','Gk (2)','Unused','Unused'].map((label,index) => <button key={`${label}-${index}`} onClick={() => show(`Training ${label}`)}>{label}</button>)}</div>
    <div className="training-footer"><button onClick={cancel}>Cancel</button><button onClick={() => show('Apply Training')}>Ok</button></div>
  </section>;
}

function TrainingRow({player,view,labels}:{player:Player;view:string;labels:string[]}) {
  return <tr><td className="training-schedule">{player.position === 'GK' ? 'Gk' : 'General'}</td><td></td><td>{player.name}</td><td className="cyan">{player.position}</td>{view === 'Summary'
    ? <><td className="cyan">{player.age}</td><td>{player.form}</td><td>{player.morale}</td><td className="orange">{player.condition}</td></>
    : labels.map(label => <td key={label} className="cyan">{player.attributes.find(item => item[0] === label)?.[1] ?? '-'}</td>)}<td className="value">{player.value}</td></tr>;
}

export function TacticsScreen({ club, onClose, show }: CommonProps) {
  const players = clubPlayers(club.id);
  const [tab, setTab] = useState('Overview');
  const starters = players.slice(0, 11);
  return <section className="tactics-screen">
    <div className="tactics-tools"><button onClick={() => show('Tactics selection')}>Tactics ▾</button><button onClick={() => show('Tactics View')}>View ▾</button><span /><button onClick={() => show('Tactics Last Match')}>Last Match</button><button onClick={() => show('Edit Tactics')}>Edit ▾</button></div>
    <div className="tactics-body"><div className="tactics-list"><h2>Demo 4-4-2</h2>{players.map(player => <div key={player.id}><b>{player.squadNumber}</b><span>{player.name}</span><em>{player.condition}</em></div>)}</div><div className="tactics-right"><nav className="tactics-tabs">{['Overview','With Ball','Without Ball'].map(label => <button key={label} className={label === tab ? 'active' : ''} onClick={() => setTab(label)}>{label}</button>)}</nav><div className="tactics-pitch"><div className="pitch-center" />{starters.map((player,index) => <div key={player.id} className="pitch-player" style={{left:`${[50,16,38,62,84,25,50,75,30,70,50][index]}%`,top:`${[90,73,73,73,73,52,53,52,30,30,12][index]}%`}}><span>{player.squadNumber}</span><small>{player.name.split(' ').at(-1)}</small></div>)}</div></div></div>
    <div className="training-footer"><button onClick={onClose}>Cancel</button><button onClick={() => show('Apply Tactics')}>Ok</button></div>
  </section>;
}

const recordRows = [
  'Highest League Position','Lowest League Position','Highest Attendance','Highest Gate Receipts',
  'Lowest Attendance','Average Attendance','Biggest Win','Biggest League Win',
  'Biggest Defeat','Highest Scoring Game','Most Games Won in Row','Most Games Lost in Row',
  'Most Games Without Losing','Top Goalscorer','Top League Goalscorer',
];
export function ClubHistory({ club, onClose, show }: CommonProps) {
  const [tab, setTab] = useState('Records');
  const [period, setPeriod] = useState('Modern Day');
  const [menu, setMenu] = useState(false);
  const completed = demoData.fixtures.filter(fixture =>
    (fixture.homeClubId === club.id || fixture.awayClubId === club.id) && fixture.homeScore !== undefined);
  const scores = completed.map(fixture => {
    const home = fixture.homeClubId === club.id;
    return { for: home ? fixture.homeScore! : fixture.awayScore!, against: home ? fixture.awayScore! : fixture.homeScore!, opponent: demoData.clubs[home ? fixture.awayClubId : fixture.homeClubId].shortName };
  });
  const win = scores.find(result => result.for > result.against);
  const loss = scores.find(result => result.for < result.against);
  const highest = [...scores].sort((a,b) => b.for + b.against - a.for - a.against)[0];
  const [firstPlayer, secondPlayer] = clubPlayers(club.id);
  const seasonValues = [
    'League season not started','League season not started','12,640','£18,900','12,640','12,640',
    win ? `${win.for}-${win.against} v ${win.opponent}` : '—',
    win ? `${win.for}-${win.against} v ${win.opponent}` : '—',
    loss ? `${loss.for}-${loss.against} v ${loss.opponent}` : '—',
    highest ? `${highest.for}-${highest.against} v ${highest.opponent}` : '—',
    win ? '1' : '0',loss ? '1' : '0',loss ? '0' : '1','Scorers not recorded','Scorers not recorded',
  ];
  const historicValues = [
    `4th in ${club.division} 2001/2`,`12th in ${club.division} 1999/00`,'19,265 — 2001/2',
    '£23,476 — 2001/2','11,843 — 1999/00','15,110 — 2001/2',
    '4-0 v Copperdale — 2001/2','3-0 v Thornby — 2000/1','0-3 v Northmere — 1999/00',
    '4-3 v Westhaven — 2001/2','4 — 2001/2','3 — 1999/00','8 — 2001/2',
    `${firstPlayer?.name ?? 'Fictional player'} — 22, 2001/2`,
    `${secondPlayer?.name ?? 'Fictional player'} — 17, 2000/1`,
  ];
  const values = period === 'This Season' ? seasonValues : historicValues;
  return <section className="club-history-screen">
    <nav className="tabs" aria-label="Club history tabs">{['Competitions','Landmarks','Records','Positions','Attendances'].map(label => <button key={label} className={tab === label ? 'active' : ''} onClick={() => label === 'Records' ? setTab(label) : show(`Club History ${label}`)}>{label}</button>)}</nav>
    <div className="history-toolbar"><button onClick={() => setMenu(!menu)}>View ▾</button></div>
    {menu && <div className="history-popup" role="menu" aria-label="History View">{['Modern Day','This Season'].map(label => <button key={label} role="menuitem" onClick={() => { setPeriod(label); setMenu(false); }}>{period === label ? '✓ ' : ''}{label}</button>)}</div>}
    <div className="club-history-body"><h2>{period}</h2><div className="history-rows">{recordRows.map((label,index) => <div key={label}><strong>{label}</strong><span>{values[index]}</span></div>)}</div></div>
    <div className="training-groups">{['Results','Sequences','Players','Transfers'].map(label => <button key={label} onClick={() => show(`Club History ${label}`)}>{label}</button>)}</div>
    <div className="game-footer"><button onClick={onClose}>Back</button><button disabled>Next</button></div>
  </section>;
}
