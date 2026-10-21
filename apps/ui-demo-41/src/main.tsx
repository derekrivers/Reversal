import { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { demoData } from './data';
import type { Club, Fixture, Player } from './types';
import { ClubModes } from './screens/ClubModes';
import type { ClubDetailMode, ClubSubview } from './screens/ClubModes';
import { PlayerModes } from './screens/PlayerModes';
import type { PlayerDetailMode, PlayerHistoryView } from './screens/PlayerModes';
import { ClubHistory, TacticsScreen, TrainingScreen } from './screens/TrainingTactics';
import { usePopupDismiss } from './usePopupDismiss';
import { MatchScreens } from './screens/MatchScreens';
import type { MatchMode, MatchPhase, MatchTab } from './screens/MatchScreens';
import { CompetitionScreens } from './screens/CompetitionScreens';
import type { CompetitionKind, CompetitionMode } from './screens/CompetitionScreens';
import { GlobalScreens } from './screens/GlobalScreens';
import type { GlobalMode } from './screens/GlobalScreens';
import './style.css';

type ClubTab = 'squad' | ClubDetailMode;
type PlayerTab = 'profile' | PlayerDetailMode;
type SquadView = 'Selection' | 'Attributes';
type View =
  | { kind: 'setup' }
  | { kind: 'restore'; selected: boolean }
  | { kind: 'fixtures'; mode: 'fixtures' | 'results' }
  | { kind: 'club'; clubId: string; tab: ClubTab; squadView?: SquadView; squadAttributeGroup?: string; subview?: ClubSubview }
  | { kind: 'player'; playerId: string; tab: PlayerTab; historyView?: PlayerHistoryView }
  | { kind: 'training' | 'tactics' | 'club-history'; clubId: string }
  | { kind: 'competition'; competition: CompetitionKind; mode: CompetitionMode; selectedGroup: string }
  | { kind: 'global'; mode: GlobalMode; tab: string; page: number; query: string }
  | { kind: 'match'; mode: MatchMode; tab: MatchTab; phase: MatchPhase };

interface RouteState { demo: true; view: View; depth: number }
interface Notice { title: string; detail: string }
const initialRoute: RouteState = { demo: true, view: { kind: 'setup' }, depth: 0 };

const unavailable = (label: string): Notice => ({
  title: `${label} unavailable`,
  detail: 'This control performs a game operation or opens a screen outside the current navigation demo. No game state has changed.'
});

function App() {
  const [route, setRoute] = useState<RouteState>(() => window.history.state?.demo ? window.history.state as RouteState : initialRoute);
  const [menu, setMenu] = useState<string | null>(null);
  const [notice, setNotice] = useState<Notice | null>(null);
  const view = route.view;
  const managedClub = demoData.clubs[demoData.managedClubId];

  useEffect(() => {
    if (!window.history.state?.demo) window.history.replaceState(initialRoute, '', window.location.pathname);
    const onPop = (event: PopStateEvent) => {
      setRoute(event.state?.demo ? event.state as RouteState : initialRoute);
      setMenu(null);
      setNotice(null);
    };
    window.addEventListener('popstate', onPop);
    return () => window.removeEventListener('popstate', onPop);
  }, []);
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') { setNotice(null); setMenu(null); }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  function show(label: string) { setMenu(null); setNotice(unavailable(label)); }
  function go(nextView: View, replace = false) {
    const next: RouteState = { demo: true, view: nextView, depth: replace ? route.depth : route.depth + 1 };
    window.history[replace ? 'replaceState' : 'pushState'](next, '', window.location.pathname);
    setRoute(next); setMenu(null); setNotice(null);
  }
  function setClubTab(tab: ClubTab) {
    if (view.kind === 'club') go({ ...view, tab }, true);
  }
  function setPlayerTab(tab: PlayerTab) {
    if (view.kind === 'player') go({ ...view, tab }, true);
  }
  function openClubBottom(kind: 'training' | 'tactics' | 'club-history') {
    if (view.kind === 'club') go({ kind, clubId: view.clubId });
  }
  function openCompetition(competition: CompetitionKind = 'cup', mode: CompetitionMode = 'stages') {
    go({ kind: 'competition', competition, mode, selectedGroup: demoData.competition.groups[0].id });
  }
  function openGlobal(mode: GlobalMode, tab = '', page = 1) { go({ kind: 'global', mode, tab, page, query: '' }); }
  function openMatch(mode: MatchMode) { go({ kind: 'match', mode, tab: 'ratings', phase: 'pre-kickoff' }); }
  function back() { if (route.depth > 0) window.history.back(); }
  function reset(nextView: View = { kind: 'setup' }) {
    const next: RouteState = { demo: true, view: nextView, depth: 0 };
    window.history.replaceState(next, '', window.location.pathname);
    setRoute(next); setMenu(null); setNotice(null);
  }
  function toggleMenu(name: string) { setNotice(null); setMenu(current => current === name ? null : name); }

  const club = 'clubId' in view ? demoData.clubs[view.clubId] : undefined;
  const player = view.kind === 'player' ? demoData.players[view.playerId] : undefined;
  const header = view.kind === 'fixtures' ? demoData.competition.name
    : view.kind === 'competition' ? view.competition === 'cup' ? demoData.competition.name : managedClub.division
    : view.kind === 'global' ? view.mode === 'find' ? `Find ${view.tab === 'Non-Player' ? 'Non-Player' : view.tab || 'Player'}` : globalHeaders[view.mode]
    : view.kind === 'club' ? club?.name
    : view.kind === 'player' ? `${player?.squadNumber}. ${player?.name} (${demoData.clubs[player?.clubId ?? '']?.shortName ?? ''})`
    : view.kind === 'training' ? `${club?.shortName} Training`
    : view.kind === 'tactics' ? `${club?.name} Tactics`
    : view.kind === 'club-history' ? `${club?.shortName} History`
    : 'Championship Manager 2001/02';
  const backEnabled = route.depth > 0 && view.kind !== 'setup';

  return <div className="demo-page">
    <div className="demo-toolbar"><strong>REVERSAL · SYNTHETIC DEMO</strong><span>Explore a fictional 2003 season</span>
      <button onClick={() => reset({ kind: 'setup' })}>Reset to menu</button>
      <button onClick={() => reset({ kind: 'fixtures', mode: 'fixtures' })}>Start at fixtures</button>
      <button onClick={() => reset({ kind: 'fixtures', mode: 'results' })}>Start at results</button>
      <button onClick={() => reset({ kind: 'match', mode: 'reference', tab: 'ratings', phase: 'pre-kickoff' })}>Static match reference</button>
      {view.kind === 'match' && view.mode === 'reference' && <select aria-label="Static match phase" value={view.phase} onChange={event => go({...view,phase:event.target.value as MatchPhase},true)}>{(['pre-kickoff','running','half-time','full-time'] as MatchPhase[]).map(phase => <option key={phase} value={phase}>{phase.replace('-', ' ')}</option>)}</select>}
    </div>
    <div className="game" aria-label="Synthetic Championship Manager interface demonstration">
      <aside className="rail">
        <div className="rail-date">{demoData.dateLabel}</div>
        <div className="rail-arrows"><button onClick={() => show('Previous date')}>◀</button><button onClick={() => show('Next date')}>▶</button></div>
        <button className="rail-item" onClick={() => show('Continue Game')}>Continue<br/>Game</button>
        <button className="rail-item manager" onClick={() => toggleMenu('manager')}>{managedClub.manager.split(' ')[0]}<br/>{managedClub.manager.split(' ').slice(1).join(' ')}</button>
        <button className="rail-item" onClick={() => toggleMenu('competitions')}>Competitions</button>
        <button className="rail-item" onClick={() => toggleMenu('nations')}>Nations<br/>&amp; Clubs</button>
        <button className="rail-item" onClick={() => toggleMenu('find')}>Find</button>
        <button className="rail-item options" onClick={() => toggleMenu('options')}>Game<br/>Options</button>
        <button className="rail-news" onClick={() => openGlobal('news','all')}>You Have<br/>News</button>
      </aside>
      {menu && <Menu name={menu} managedClub={managedClub} openClub={() => go({kind:'club',clubId:managedClub.id,tab:'squad'})} openFixtures={() => go({kind:'fixtures',mode:'fixtures'})} openCompetition={openCompetition} openGlobal={openGlobal} show={show} close={() => setMenu(null)} />}
      <main className={`game-main ${view.kind === 'setup' || view.kind === 'restore' ? 'menu-background' : ''} ${view.kind === 'training' ? 'training-background' : ''} ${view.kind === 'match' ? 'match-background' : ''}`}>
        {view.kind !== 'match' && <header className={`game-header ${view.kind === 'fixtures' || view.kind === 'competition' ? 'blue' : view.kind === 'global' && ['find','manager-status','selected-leagues'].includes(view.mode) ? 'red' : 'black'}`}><span className="header-arrow">▸</span><h1>{header}</h1>{view.kind === 'club' || view.kind === 'player' || view.kind === 'competition' ? <button className="header-action" onClick={() => show(view.kind === 'player' ? 'Action' : 'Print')}>{view.kind === 'player' ? 'Action ▾' : 'Print ▾'}</button> : null}</header>}
        {view.kind === 'setup' && <Setup openRestore={() => go({kind:'restore',selected:false})} show={show} />}
        {view.kind === 'restore' && <Restore selected={view.selected} select={() => go({kind:'restore',selected:true},true)} proceed={() => reset({kind:'fixtures',mode:'fixtures'})} cancel={back} show={show} />}
        {view.kind === 'fixtures' && <Fixtures mode={view.mode} clubClick={clubId => go({kind:'club',clubId,tab:'squad'})} openCompetition={() => openCompetition('cup')} show={show} />}
        {view.kind === 'competition' && <CompetitionScreens kind={view.competition} mode={view.mode} selectedGroup={view.selectedGroup} onMode={mode => go({...view,mode},true)} onGroup={selectedGroup => go({...view,selectedGroup},true)} onClub={clubId => go({kind:'club',clubId,tab:'squad'})} show={show} />}
        {view.kind === 'global' && <GlobalScreens mode={view.mode} tab={view.tab} page={view.page} query={view.query} onTab={tab => go({...view,tab,query:'',page:1},true)} onPage={page => go({...view,page},true)} onQuery={query => go({...view,query,page:1},true)} onPlayer={playerId => go({kind:'player',playerId,tab:'profile'})} onClub={clubId => go({kind:'club',clubId,tab:'squad'})} onClose={back} show={show} />}
        {view.kind === 'match' && <MatchScreens mode={view.mode} tab={view.tab} phase={view.phase} onTab={tab => go({...view,tab},true)} show={show} />}
        {club && view.kind === 'club' && <section className="club-screen">
          <nav className="tabs" aria-label="Club tabs">{clubTabs.map(([label, tab]) => <button key={tab} className={view.tab === tab ? 'active' : ''} onClick={() => setClubTab(tab)}>{label}</button>)}</nav>
          {view.tab === 'squad'
            ? <ClubScreen club={club} players={Object.values(demoData.players).filter(item => item.clubId === club.id)} squadView={view.squadView ?? 'Selection'} attributeGroup={view.squadAttributeGroup ?? 'Physical'} onSquadView={squadView => go({...view,squadView},true)} onGroup={squadAttributeGroup => go({...view,squadAttributeGroup},true)} openPlayer={playerId => go({kind:'player',playerId,tab:'profile'})} show={show} />
            : <ClubModes key={view.tab} club={club} mode={view.tab} subview={view.subview} onSubview={subview => go({...view,subview},true)} onClub={clubId => go({kind:'club',clubId,tab:'squad'})} onPlayer={playerId => go({kind:'player',playerId,tab:'profile'})} show={show} />}
          <div className="bottom-strip">{['Tactics','Training','Last Match',club.division,'History'].map(label => <button key={label} onClick={() => label === 'Tactics' ? openClubBottom('tactics') : label === 'Training' ? openClubBottom('training') : label === 'Last Match' ? openMatch('last-match') : label === club.division ? openCompetition('league','table') : openClubBottom('club-history')}>{label} ▸</button>)}</div>
        </section>}
        {player && view.kind === 'player' && <section className="player-screen">
          <nav className="tabs" aria-label="Player tabs">{profileTabs.map(([label, tab]) => <button key={tab} className={view.tab === tab ? 'active' : ''} onClick={() => setPlayerTab(tab)}>{label}</button>)}</nav>
          {view.tab === 'profile' ? <PlayerScreen player={player} /> : <PlayerModes player={player} mode={view.tab} historyView={view.historyView} onHistoryView={historyView => go({...view,historyView},true)} show={show} />}
        </section>}
        {club && view.kind === 'training' && <TrainingScreen club={club} onClose={back} show={show} />}
        {club && view.kind === 'tactics' && <TacticsScreen club={club} onClose={back} show={show} />}
        {club && view.kind === 'club-history' && <ClubHistory club={club} onClose={back} show={show} />}
        {!['training','tactics','club-history'].includes(view.kind) && <footer className="game-footer"><button disabled={!backEnabled} onClick={back}>Back</button><button disabled title="Navigation is not observed for this control">Next</button></footer>}
      </main>
      {notice && <div className="dialog-layer" onMouseDown={event => { if (event.target === event.currentTarget) setNotice(null); }}><div className="dialog" role="dialog" aria-modal="true" aria-label={notice.title}><h2>{notice.title}</h2><p>{notice.detail}</p><button onClick={() => setNotice(null)}>Close</button></div></div>}
    </div>
  </div>;
}

const globalHeaders: Record<GlobalMode,string> = {
  find: 'Find', news: 'News', 'manager-stats': 'Manager Stats', 'job-info': 'Job Information',
  'manager-transfers': 'Transfers', 'manager-history': 'History', 'board-confidence': 'Board Confidence',
  'manager-status': 'Manager Status', 'selected-leagues': 'Selected Leagues',
  'game-settings': 'Game Settings', search: 'Player & Staff Search',
};
function Menu({ name, managedClub, openClub, openFixtures, openCompetition, openGlobal, show, close }: {name:string;managedClub:Club;openClub:()=>void;openFixtures:()=>void;openCompetition:(kind:CompetitionKind,mode?:CompetitionMode)=>void;openGlobal:(mode:GlobalMode,tab?:string,page?:number)=>void;show:(label:string)=>void;close:()=>void}) {
  const lists: Record<string, string[]> = {
    manager: [`${managedClub.shortName} Squad`, `${managedClub.shortName} Reserves`, 'Board Confidence', 'News', 'Player & Staff Search', 'Manager Stats', 'Job Information', 'Transfers', 'History'],
    competitions: [demoData.competition.name, 'Domestic League', 'Domestic Cup'],
    nations: ['England', 'France', 'Germany', 'Italy', 'Spain'],
    find: ['Nation', 'Club', 'Non-Player', 'Player', 'Written History'],
    options: ['Save Game', 'Add Manager', 'Manager Status', 'Game Settings', 'Selected Leagues', 'Hall of Fame', 'Game Credits', 'Restart Game', 'Exit Game']
  };
  const top: Record<string, number> = { manager: 144, competitions: 193, nations: 240, find: 285, options: 332 };
  return <div className="menu-scrim" onMouseDown={close}><div className="green-menu" style={{top:top[name] ?? 144}} onMouseDown={event => event.stopPropagation()} role="menu" aria-label={`${name} menu`}>
    {(lists[name] ?? []).map((label,index) => <button key={label} role="menuitem" onClick={() => {
      if (name === 'manager') {
        const managerRoutes: Record<number, GlobalMode> = {2:'board-confidence',3:'news',4:'search',5:'manager-stats',6:'job-info',7:'manager-transfers',8:'manager-history'};
        if (index === 0) return openClub();
        if (managerRoutes[index]) return openGlobal(managerRoutes[index]);
      }
      if (name === 'competitions') { if (index === 0) return openFixtures(); return openCompetition(index === 1 ? 'league' : 'cup', index === 1 ? 'table' : 'stages'); }
      if (name === 'find' && index < 4) return openGlobal('find',label.toLowerCase());
      if (name === 'options') { const optionRoutes: Record<number,GlobalMode> = {2:'manager-status',3:'game-settings',4:'selected-leagues'}; if (optionRoutes[index]) return openGlobal(optionRoutes[index]); }
      show(label);
    }}>{label}</button>)}
  </div></div>;
}

function Setup({openRestore,show}:{openRestore:()=>void;show:(label:string)=>void}) {
  return <section className="setup-screen"><h2>Setup Game</h2><div className="setup-options">{['Start New Game','Quick Start Game','Restore Saved Game','Network Game','Game Settings','Exit Game'].map(label => <button key={label} onClick={label === 'Restore Saved Game' ? openRestore : () => show(label)}>{label}</button>)}</div><p>Fictional clubs and players · navigation demonstration</p></section>;
}

function Restore({selected,select,proceed,cancel,show}:{selected:boolean;select:()=>void;proceed:()=>void;cancel:()=>void;show:(label:string)=>void}) {
  return <section className="restore-screen"><h2>Restore Saved Game</h2><div className="restore-panel"><strong>Select File</strong><button className={selected?'selected':''} onClick={select}>demo-season.sav</button><label>File <input readOnly value={selected?'demo-season.sav':''} /></label></div><div className="restore-actions"><button onClick={cancel}>Cancel</button><button onClick={() => show('Save Info')}>Info</button><button disabled={!selected} onClick={proceed}>Ok</button></div><p>This is a synthetic entry point. No save file is loaded.</p></section>;
}

function clubName(id:string) { return demoData.clubs[id]?.shortName ?? id; }
function Fixtures({mode,clubClick,openCompetition}:{mode:'fixtures'|'results';clubClick:(id:string)=>void;openCompetition:()=>void;show:(label:string)=>void}) {
  const games = demoData.fixtures.filter(item => mode === 'results' ? item.homeScore !== undefined : item.homeScore === undefined);
  const phases = [...new Set(games.map(item => item.phase))];
  return <section className="fixtures-screen"><h2>Evening {mode === 'results' ? 'Results' : 'Fixtures'}</h2><div className="fixture-toolbar"><button onClick={openCompetition}>Competition</button></div><div className="fixture-list">{phases.map(phase => <div key={phase} className="fixture-phase"><h3>{phase}</h3>{games.filter(item => item.phase===phase).map(item => <FixtureRow key={item.id} fixture={item} clubClick={clubClick} />)}</div>)}</div></section>;
}
function FixtureRow({fixture,clubClick}:{fixture:Fixture;clubClick:(id:string)=>void}) {
  return <div className="fixture-row"><span className="place">{fixture.homeScore === undefined?'2nd':'1st'}</span><button className="fixture-club" onClick={() => clubClick(fixture.homeClubId)}>{clubName(fixture.homeClubId)}</button><span className="fixture-score">{fixture.homeScore === undefined?'v':`${fixture.homeScore} : ${fixture.awayScore}`}</span><button className="fixture-club" onClick={() => clubClick(fixture.awayClubId)}>{clubName(fixture.awayClubId)}</button><span className="place">{fixture.awayScore === undefined?'3rd':'4th'}</span></div>;
}

const clubTabs: ReadonlyArray<readonly [string, ClubTab]> = [
  ['Squad', 'squad'], ['Transfers', 'transfers'], ['Next Match', 'next-match'],
  ['Fixtures', 'fixtures'], ['Finances & Info', 'info'],
];
const squadViewItems = ['Traditional', 'Contract', 'Selection', 'Stats', 'More Stats', 'Attributes', 'Other', 'Penalty Takers'];
const attributeGroups = ['Physical', 'Mental', 'Goalkeeping', 'Defensive', 'Attacking'];
const groupLabels: Record<string, string[]> = {
  Physical: ['Acceleration', 'Agility', 'Balance', 'Jumping', 'Pace', 'Stamina', 'Strength'],
  Mental: ['Aggression', 'Anticipation', 'Bravery', 'Decisions', 'Determination', 'Influence', 'Teamwork'],
  Goalkeeping: ['Handling', 'Reflexes', 'Positioning', 'Decisions', 'Agility', 'Jumping', 'Bravery'],
  Defensive: ['Marking', 'Tackling', 'Positioning', 'Heading', 'Strength', 'Teamwork', 'Work Rate'],
  Attacking: ['Crossing', 'Dribbling', 'Finishing', 'Long Shots', 'Off The Ball', 'Passing', 'Technique'],
};
function ClubScreen({players,squadView,attributeGroup,onSquadView,onGroup,openPlayer,show}:{
  club:Club;players:Player[];squadView:SquadView;attributeGroup:string;
  onSquadView:(view:SquadView)=>void;onGroup:(group:string)=>void;
  openPlayer:(id:string)=>void;show:(label:string)=>void;
}) {
  const [viewMenu, setViewMenu] = useState(false);
  const [categoryMenu, setCategoryMenu] = useState(false);
  usePopupDismiss(viewMenu || categoryMenu, () => { setViewMenu(false); setCategoryMenu(false); }, '.squad-view-menu,.squad-category-menu,.squad-view-trigger');
  const labels = groupLabels[attributeGroup] ?? groupLabels.Physical;
  function chooseView(label:string) {
    setViewMenu(false);
    if (label === 'Selection' || label === 'Attributes') {
      onSquadView(label);
      setCategoryMenu(label === 'Attributes');
    } else show(`Squad ${label} view`);
  }
  return <>
    <div className="subtools"><button className="squad-view-trigger" onClick={() => setViewMenu(!viewMenu)}>View ▾</button><h2>{squadView} Info</h2><button onClick={() => show('Clear Squad')}>Clear Squad</button><button onClick={() => show('Filter')}>Filter ▾</button></div>
    {viewMenu && <div className="squad-view-menu" role="menu" aria-label="Squad View">{squadViewItems.map(label => <button key={label} role="menuitem" onClick={() => chooseView(label)}>{squadView===label?'✓ ':''}{label}</button>)}</div>}
    {categoryMenu && <div className="squad-category-menu" role="menu" aria-label="Attribute categories">{attributeGroups.map(label => <button key={label} role="menuitem" onClick={() => { onGroup(label); setCategoryMenu(false); }}>{attributeGroup===label?'✓ ':''}{label}</button>)}</div>}
    <div className="roster-scroller"><table className="roster"><thead><tr>{squadView === 'Selection'
      ? ['Pkd','Inf','Name','Position','Form','Morale','Cond.','Apps','Av R','Value'].map(label=><th key={label}>{label}</th>)
      : ['Pkd','Inf','Name','Position',...labels.map(label => label.slice(0,3)),'Value'].map((label,index)=><th key={`${label}-${index}`}>{label}</th>)}</tr></thead><tbody>{players.map(player => squadView === 'Selection'
      ? <tr key={player.id}><td className="picked"></td><td></td><td className="name"><button onClick={() => openPlayer(player.id)}>{player.name}</button></td><td className="cyan">{player.position}</td><td>{player.form}</td><td>{player.morale}</td><td className="orange">{player.condition}</td><td className="cyan">{player.appearances}</td><td className="cyan">{player.averageRating}</td><td className="value">{player.value}</td></tr>
      : <tr key={player.id}><td className="picked"></td><td></td><td className="name"><button onClick={() => openPlayer(player.id)}>{player.name}</button></td><td className="cyan">{player.position}</td>{labels.map(label => <td key={label} className="cyan">{player.attributes.find(item => item[0] === label)?.[1] ?? '-'}</td>)}<td className="value">{player.value}</td></tr>)}</tbody></table></div>
  </>;
}

const profileTabs: ReadonlyArray<readonly [string, PlayerTab]> = [
  ['Profile', 'profile'], ['Injuries & Bans', 'injuries-bans'], ['Contract', 'contract'],
  ['Transfer', 'transfer'], ['History', 'history'],
];
function PlayerScreen({player}:{player:Player}) {
  const columns=[player.attributes.slice(0,12),player.attributes.slice(12,24),player.attributes.slice(24,31)];
  return <><h2 className="player-bio">Born {player.born} (Age {player.age}). {player.nationality}.</h2><div className="attributes">{columns.map((column,index)=><div key={index}>{column.map(([label,value])=><div className="attribute" key={label}><span>{label}</span><strong>{value}</strong></div>)}{index===2&&[['Preferred Foot',player.preferredFoot],['Form',player.form],['Morale',player.morale],['Condition',player.condition]].map(([label,value])=><div className="attribute" key={label}><span>{label}</span><strong className="orange">{value}</strong></div>)}</div>)}</div><div className="player-stats"><div className="stat-head"><span></span>{['Apps','Con','Asts','MoM','Pass','Tck','Drb','Av R'].map(v=><span key={v}>{v}</span>)}</div>{['Non Competitive','League','Cup','Continental','International','Senior Club'].map((row,i)=><div className="stat-row" key={row}><span>{row}</span><span>{i*3+2}</span><span>{i+1}</span><span>{i===1?2:0}</span><span>0</span><span>{i?`${50+i}%`:'-'}</span><span>{i?`${(i/3).toFixed(1)}`:'-'}</span><span>0.0</span><span className="rating">{i?`${(6.4+i/10).toFixed(2)}`:'-----'}</span></div>)}</div><div className="player-role">{player.position.startsWith('GK')?'Goalkeeper':'Footballer'}</div></>;
}

createRoot(document.getElementById('root')!).render(<App />);
