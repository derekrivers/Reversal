import { demoData } from '../data';
import type { Club, Fixture, Player } from '../types';
import './MatchScreens.css';

export type MatchMode = 'last-match' | 'reference';
export type MatchTab = 'ratings' | 'overview' | 'stats' | 'zones' | 'report';
export type MatchPhase = 'pre-kickoff' | 'running' | 'half-time' | 'full-time';

interface MatchProps {
  mode: MatchMode;
  tab: MatchTab;
  phase: MatchPhase;
  clubId: string;
  onTab: (tab: MatchTab) => void;
  show: (label: string) => void;
}

const completedFixtures = demoData.fixtures.filter(item => item.homeScore !== undefined && item.awayScore !== undefined);
const matchTabs: ReadonlyArray<readonly [MatchTab, string]> = [
  ['overview', 'Match Overview'], ['stats', 'Match Stats'], ['zones', 'Action Zones'], ['report', 'Match Report'],
];

export function MatchScreens({ mode, tab, phase, clubId, onTab, show }: MatchProps) {
  const fixture = completedFixtures.find(item => item.homeClubId === clubId || item.awayClubId === clubId) ?? completedFixtures[0];
  const home = demoData.clubs[fixture.homeClubId];
  const away = demoData.clubs[fixture.awayClubId];
  const homePlayers = Object.values(demoData.players).filter(player => player.clubId === home.id);
  const awayPlayers = Object.values(demoData.players).filter(player => player.clubId === away.id);
  const activePhase = mode === 'last-match' ? 'full-time' : phase;
  const homeScore = activePhase === 'full-time' ? fixture.homeScore! : activePhase === 'half-time' && fixture.homeScore! > 0 ? 1 : 0;
  const awayScore = activePhase === 'full-time' ? fixture.awayScore! : 0;
  return <section className="match-screen" aria-label={mode === 'last-match' ? 'Last Match' : `Static ${phase} match reference`}>
    <div className="match-scoreboard"><div className="match-side home"><span>{home.shortName}</span><strong>{homeScore}</strong></div><div className="match-side away"><span>{away.shortName}</span><strong>{awayScore}</strong></div></div>
    <nav className="match-tabs" aria-label="Match views">{matchTabs.map(([id,label]) => <button key={id} className={tab === id ? 'active' : ''} onClick={() => onTab(id)}>{label}</button>)}</nav>
    <div className="match-content">
      {mode === 'reference' && <div className="match-reference-label">Static {phase.replace('-', ' ')} reference · no match simulation</div>}
      {tab === 'ratings' && <Ratings homePlayers={homePlayers} awayPlayers={awayPlayers} phase={activePhase} />}
      {tab === 'overview' && <Overview fixture={fixture} home={home} away={away} mode={mode} phase={activePhase} />}
      {tab === 'stats' && <MatchStats phase={activePhase} />}
      {tab === 'zones' && <ActionZones phase={activePhase} show={show} />}
      {tab === 'report' && <MatchReport fixture={fixture} home={home} away={away} phase={activePhase} />}
    </div>
    <div className="match-bottom"><button onClick={() => onTab('stats')}>{home.shortName} Stats</button><button className={tab === 'ratings' ? 'active' : ''} onClick={() => onTab('ratings')}>Player Ratings</button><button onClick={() => onTab('stats')}>{away.shortName} Stats</button></div>
  </section>;
}

function Ratings({homePlayers,awayPlayers,phase}:{homePlayers:Player[];awayPlayers:Player[];phase:MatchPhase}) {
  return <div className="match-ratings">{[[homePlayers, 'home'],[awayPlayers, 'away']].map(([players,side]) => <div key={side as string} className="match-team-ratings">{(players as Player[]).map((player,index) => <div key={player.id}><b>{player.squadNumber}</b><span>{player.name}</span><em>{phase === 'pre-kickoff' || index >= 11 ? '—' : 6 + (index % 3)}</em></div>)}</div>)}</div>;
}

function Overview({fixture,home,away,mode,phase}:{fixture:Fixture;home:Club;away:Club;mode:MatchMode;phase:MatchPhase}) {
  const events = phase === 'full-time'
    ? [[`${home.shortName} open brightly`,'18'],[`${away.shortName} press forward`,'62'],['Late chances at both ends','88']]
    : phase === 'half-time' ? (fixture.homeScore! > 0 ? [[`${home.shortName} score`,'34']] : [['The teams trade chances','34']])
    : phase === 'running' ? [['Both sides trade early chances','18']] : [];
  return <div className="match-overview"><h2>{home.stadium}</h2><div className="match-overview-meta"><span>Saturday 12th July 2003</span><span>North Coast Cup / {mode === 'last-match' ? `FT ${fixture.homeScore}-${fixture.awayScore}` : phase.replace('-', ' ')}</span></div>
    {events.length ? <div className="match-events">{events.map(([event,minute]) => <div key={minute}><strong>{event}</strong><b>{minute}</b></div>)}</div> : <p className="match-waiting">Teams are ready. Kick Off is an unavailable game operation in this navigation demo.</p>}
    <div className="match-overview-footer"><span>Referee — Ellis Morton</span><span>Attendance — 12,640</span><span>Weather — Dry, 18°C</span></div>
  </div>;
}

const statRows: ReadonlyArray<readonly [string,string,string]> = [
  ['Shots On Goal','7','6'], ['On Target','3','3'], ['Off Target','4','3'],
  ['Corners','5','4'], ['Free Kicks','13','12'], ['Throw-Ins','17','16'],
  ['Fouls','8','9'], ['Offsides','2','3'], ['Passes Completed','74%','71%'],
  ['Tackles Won','61%','59%'], ['Headers Won','52%','49%'],
  ['Yellow Cards','1','2'], ['Red Cards','0','0'],
];
function MatchStats({phase}:{phase:MatchPhase}) {
  const fraction = phase === 'pre-kickoff' ? 0 : phase === 'running' ? .25 : phase === 'half-time' ? .5 : 1;
  const valueAtPhase = (value:string) => value.endsWith('%') ? (fraction ? value : '0%') : String(Math.round(Number(value) * fraction));
  return <div className="match-stats">{statRows.map(([label,left,right]) => <div key={label}><b>{valueAtPhase(left)}</b><strong>{label}</strong><b>{valueAtPhase(right)}</b></div>)}</div>;
}

function ActionZones({phase,show}:{phase:MatchPhase;show:(label:string)=>void}) {
  const values = phase === 'pre-kickoff' ? [0,0,0,0,0] : phase === 'running' ? [30,42,28,51,49] : phase === 'half-time' ? [28,47,25,53,47] : [27,49,24,55,45];
  return <div className="match-zones"><button onClick={() => show('Action Zones View')}>View ▾</button><div className="zones-pitch"><div className="zones-markings">{values.slice(0,3).map((value,index) => <i key={index}>{value}%</i>)}</div></div><div className="zones-bars" style={{background:phase === 'pre-kickoff' ? '#111' : `linear-gradient(90deg,#111 ${values[3]}%,#b51313 ${values[3]}%)`}}><span>{values[3]}%</span><span>{values[4]}%</span></div></div>;
}

function MatchReport({fixture,home,away,phase}:{fixture:Fixture;home:Club;away:Club;phase:MatchPhase}) {
  const allEvents = phase === 'pre-kickoff' ? [
    ['0 min','The teams are ready to take the field.'],
  ] : [
    ['2 min',`${home.shortName} move the ball into midfield.`],
    ['17 min',`${away.shortName} break down the right side.`],
    ['34 min',fixture.homeScore! > 0 ? `${home.shortName} score from close range.` : 'The teams trade chances.'],
    ['45 min','Half-time arrives after an even first half.'],
    ['62 min',`${away.shortName} press forward.`],
    ['82 min',`${home.shortName} create another chance.`],
    ['88 min',fixture.awayScore! > 0 ? `${away.shortName} find the net.` : `${away.shortName} come close.`],
    ['90 min','The referee brings the match to a close.'],
  ];
  const limit = phase === 'full-time' ? 90 : phase === 'half-time' ? 45 : phase === 'running' ? 20 : 0;
  const events = allEvents.filter(([minute]) => Number.parseInt(minute, 10) <= limit);
  return <div className="match-report">{events.map(([minute,text]) => <div key={minute}><b>{minute}</b><span>{text}</span></div>)}</div>;
}
