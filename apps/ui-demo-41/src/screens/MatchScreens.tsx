import { demoData } from '../data';
import type { Player } from '../types';
import './MatchScreens.css';

export type MatchMode = 'last-match' | 'reference';
export type MatchTab = 'ratings' | 'overview' | 'stats' | 'zones' | 'report';
export type MatchPhase = 'pre-kickoff' | 'running' | 'half-time' | 'full-time';

interface MatchProps {
  mode: MatchMode;
  tab: MatchTab;
  phase: MatchPhase;
  onTab: (tab: MatchTab) => void;
  show: (label: string) => void;
}

const fixture = demoData.fixtures.find(item => item.homeClubId === demoData.managedClubId && item.homeScore !== undefined)!;
const home = demoData.clubs[fixture.homeClubId];
const away = demoData.clubs[fixture.awayClubId];
const homePlayers = Object.values(demoData.players).filter(player => player.clubId === home.id);
const awayPlayers = Object.values(demoData.players).filter(player => player.clubId === away.id);
const matchTabs: ReadonlyArray<readonly [MatchTab, string]> = [
  ['overview', 'Match Overview'], ['stats', 'Match Stats'], ['zones', 'Action Zones'], ['report', 'Match Report'],
];

export function MatchScreens({ mode, tab, phase, onTab, show }: MatchProps) {
  const homeScore = mode === 'last-match' || phase === 'full-time' ? fixture.homeScore! : phase === 'half-time' ? 1 : 0;
  const awayScore = mode === 'last-match' || phase === 'full-time' ? fixture.awayScore! : 0;
  return <section className="match-screen" aria-label={mode === 'last-match' ? 'Last Match' : `Static ${phase} match reference`}>
    <div className="match-scoreboard"><div className="match-side home"><span>{home.shortName}</span><strong>{homeScore}</strong></div><div className="match-side away"><span>{away.shortName}</span><strong>{awayScore}</strong></div></div>
    <nav className="match-tabs" aria-label="Match views">{matchTabs.map(([id,label]) => <button key={id} className={tab === id ? 'active' : ''} onClick={() => onTab(id)}>{label}</button>)}</nav>
    <div className="match-content">
      {mode === 'reference' && <div className="match-reference-label">Static {phase.replace('-', ' ')} reference · no match simulation</div>}
      {tab === 'ratings' && <Ratings homePlayers={homePlayers} awayPlayers={awayPlayers} />}
      {tab === 'overview' && <Overview mode={mode} phase={phase} />}
      {tab === 'stats' && <MatchStats phase={mode === 'last-match' ? 'full-time' : phase} />}
      {tab === 'zones' && <ActionZones show={show} />}
      {tab === 'report' && <MatchReport mode={mode} phase={phase} />}
    </div>
    <div className="match-bottom"><button onClick={() => onTab('stats')}>{home.shortName} Stats</button><button className={tab === 'ratings' ? 'active' : ''} onClick={() => onTab('ratings')}>Player Ratings</button><button onClick={() => onTab('stats')}>{away.shortName} Stats</button></div>
  </section>;
}

function Ratings({homePlayers,awayPlayers}:{homePlayers:Player[];awayPlayers:Player[]}) {
  return <div className="match-ratings">{[[homePlayers, 'home'],[awayPlayers, 'away']].map(([players,side]) => <div key={side as string} className="match-team-ratings">{(players as Player[]).map((player,index) => <div key={player.id}><b>{player.squadNumber}</b><span>{player.name}</span><em>{index < 11 ? 6 + (index % 3) : '—'}</em></div>)}</div>)}</div>;
}

function Overview({mode,phase}:{mode:MatchMode;phase:MatchPhase}) {
  const events = mode === 'last-match' || phase === 'full-time'
    ? [['Ellery scores','34'],['Rowan goes close','82'],['Westhaven equalise','88']]
    : phase === 'half-time' ? [['Ellery scores','34']]
    : phase === 'running' ? [['Both sides trade early chances','18']] : [];
  return <div className="match-overview"><h2>{home.stadium}</h2><div className="match-overview-meta"><span>Saturday 12th July 2003</span><span>North Coast Cup / {mode === 'last-match' ? 'FT 1-1' : phase.replace('-', ' ')}</span></div>
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

function ActionZones({show}:{show:(label:string)=>void}) {
  return <div className="match-zones"><button onClick={() => show('Action Zones View')}>View ▾</button><div className="zones-pitch"><div className="zones-markings"><i>27%</i><i>49%</i><i>24%</i></div></div><div className="zones-bars"><span>55%</span><span>45%</span></div></div>;
}

function MatchReport({mode,phase}:{mode:MatchMode;phase:MatchPhase}) {
  const allEvents = mode === 'reference' && phase === 'pre-kickoff' ? [
    ['0 min','The teams are ready to take the field.'],
  ] : [
    ['2 min',`${home.shortName} move the ball into midfield.`],
    ['17 min',`${away.shortName} break down the right side.`],
    ['34 min',`${home.shortName} score from close range.`],
    ['45 min','Half-time arrives after an even first half.'],
    ['62 min',`${away.shortName} press for an equaliser.`],
    ['82 min',`${home.shortName} create another chance.`],
    ['88 min',`${away.shortName} equalise with a low shot.`],
    ['90 min','The referee brings the match to a close.'],
  ];
  const limit = mode === 'last-match' || phase === 'full-time' ? 90 : phase === 'half-time' ? 45 : phase === 'running' ? 20 : 0;
  const events = allEvents.filter(([minute]) => Number.parseInt(minute, 10) <= limit);
  return <div className="match-report">{events.map(([minute,text]) => <div key={minute}><b>{minute}</b><span>{text}</span></div>)}</div>;
}
