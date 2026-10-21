import { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { demoData } from './data';
import type { Club, Fixture, Player } from './types';
import './style.css';

type View =
  | { kind: 'setup' }
  | { kind: 'restore'; selected: boolean }
  | { kind: 'fixtures'; mode: 'fixtures' | 'results' }
  | { kind: 'club'; clubId: string; tab: 'squad' }
  | { kind: 'player'; playerId: string; tab: 'profile' };

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
  function back() { if (route.depth > 0) window.history.back(); }
  function reset(nextView: View = { kind: 'setup' }) {
    const next: RouteState = { demo: true, view: nextView, depth: 0 };
    window.history.replaceState(next, '', window.location.pathname);
    setRoute(next); setMenu(null); setNotice(null);
  }
  function toggleMenu(name: string) { setNotice(null); setMenu(current => current === name ? null : name); }

  const club = view.kind === 'club' ? demoData.clubs[view.clubId] : undefined;
  const player = view.kind === 'player' ? demoData.players[view.playerId] : undefined;
  const header = view.kind === 'fixtures' ? demoData.competition.name : view.kind === 'club' ? club?.name : view.kind === 'player' ? `${player?.squadNumber}. ${player?.name} (${demoData.clubs[player?.clubId ?? '']?.shortName ?? ''})` : 'Championship Manager 2001/02';
  const backEnabled = (view.kind === 'club' || view.kind === 'player' || view.kind === 'restore') && route.depth > 0;

  return <div className="demo-page">
    <div className="demo-toolbar"><strong>REVERSAL · SYNTHETIC DEMO</strong><span>Explore a fictional 2003 season</span>
      <button onClick={() => reset({ kind: 'setup' })}>Reset to menu</button>
      <button onClick={() => reset({ kind: 'fixtures', mode: 'fixtures' })}>Start at fixtures</button>
      <button onClick={() => reset({ kind: 'fixtures', mode: 'results' })}>Start at results</button>
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
        <div className="rail-news">You Have<br/>News</div>
      </aside>
      {menu && <Menu name={menu} managedClub={managedClub} openClub={() => go({kind:'club',clubId:managedClub.id,tab:'squad'})} openFixtures={() => go({kind:'fixtures',mode:'fixtures'})} show={show} close={() => setMenu(null)} />}
      <main className={`game-main ${view.kind === 'setup' || view.kind === 'restore' ? 'menu-background' : ''}`}>
        <header className={`game-header ${view.kind === 'fixtures' ? 'blue' : 'black'}`}><span className="header-arrow">▸</span><h1>{header}</h1>{view.kind === 'club' || view.kind === 'player' ? <button className="header-action" onClick={() => show(view.kind === 'player' ? 'Action' : 'Print')}>{view.kind === 'player' ? 'Action ▾' : 'Print ▾'}</button> : null}</header>
        {view.kind === 'setup' && <Setup openRestore={() => go({kind:'restore',selected:false})} show={show} />}
        {view.kind === 'restore' && <Restore selected={view.selected} select={() => go({kind:'restore',selected:true},true)} proceed={() => go({kind:'fixtures',mode:'fixtures'},true)} cancel={back} show={show} />}
        {view.kind === 'fixtures' && <Fixtures mode={view.mode} clubClick={clubId => go({kind:'club',clubId,tab:'squad'})} show={show} />}
        {club && <ClubScreen club={club} players={Object.values(demoData.players).filter(player => player.clubId === club.id)} openPlayer={playerId => go({kind:'player',playerId,tab:'profile'})} show={show} />}
        {player && <PlayerScreen player={player} show={show} />}
        <footer className="game-footer"><button disabled={!backEnabled} onClick={back}>Back</button><button disabled title="Navigation is not observed for this control">Next</button></footer>
      </main>
      {notice && <div className="dialog-layer" onMouseDown={event => { if (event.target === event.currentTarget) setNotice(null); }}><div className="dialog" role="dialog" aria-modal="true" aria-label={notice.title}><h2>{notice.title}</h2><p>{notice.detail}</p><button onClick={() => setNotice(null)}>Close</button></div></div>}
    </div>
  </div>;
}

function Menu({ name, managedClub, openClub, openFixtures, show, close }: {name:string;managedClub:Club;openClub:()=>void;openFixtures:()=>void;show:(label:string)=>void;close:()=>void}) {
  const lists: Record<string, string[]> = {
    manager: [`${managedClub.shortName} Squad`, `${managedClub.shortName} Reserves`, 'Board Confidence', 'News', 'Player & Staff Search', 'Manager Stats', 'Job Information', 'Transfers', 'History'],
    competitions: [demoData.competition.name, 'Domestic League', 'Domestic Cup'],
    nations: ['England', 'France', 'Germany', 'Italy', 'Spain'],
    find: ['Nation', 'Club', 'Non-Player', 'Player', 'Written History'],
    options: ['Save Game', 'Add Manager', 'Manager Status', 'Game Settings', 'Selected Leagues', 'Hall of Fame', 'Game Credits', 'Restart Game', 'Exit Game']
  };
  const top: Record<string, number> = { manager: 144, competitions: 193, nations: 240, find: 285, options: 332 };
  return <div className="menu-scrim" onMouseDown={close}><div className="green-menu" style={{top:top[name] ?? 144}} onMouseDown={event => event.stopPropagation()} role="menu" aria-label={`${name} menu`}>
    {(lists[name] ?? []).map((label,index) => <button key={label} role="menuitem" onClick={() => name === 'manager' && index === 0 ? openClub() : name === 'competitions' && index === 0 ? openFixtures() : show(label)}>{label}</button>)}
  </div></div>;
}

function Setup({openRestore,show}:{openRestore:()=>void;show:(label:string)=>void}) {
  return <section className="setup-screen"><h2>Setup Game</h2><div className="setup-options">{['Start New Game','Quick Start Game','Restore Saved Game','Network Game','Game Settings','Exit Game'].map(label => <button key={label} onClick={label === 'Restore Saved Game' ? openRestore : () => show(label)}>{label}</button>)}</div><p>Fictional clubs and players · navigation demonstration</p></section>;
}

function Restore({selected,select,proceed,cancel,show}:{selected:boolean;select:()=>void;proceed:()=>void;cancel:()=>void;show:(label:string)=>void}) {
  return <section className="restore-screen"><h2>Restore Saved Game</h2><div className="restore-panel"><strong>Select File</strong><button className={selected?'selected':''} onClick={select}>demo-season.sav</button><label>File <input readOnly value={selected?'demo-season.sav':''} /></label></div><div className="restore-actions"><button onClick={cancel}>Cancel</button><button onClick={() => show('Save Info')}>Info</button><button disabled={!selected} onClick={proceed}>Ok</button></div><p>This is a synthetic entry point. No save file is loaded.</p></section>;
}

function clubName(id:string) { return demoData.clubs[id]?.shortName ?? id; }
function Fixtures({mode,clubClick,show}:{mode:'fixtures'|'results';clubClick:(id:string)=>void;show:(label:string)=>void}) {
  const games = demoData.fixtures.filter(item => mode === 'results' ? item.homeScore !== undefined : item.homeScore === undefined);
  const phases = [...new Set(games.map(item => item.phase))];
  return <section className="fixtures-screen"><h2>Evening {mode === 'results' ? 'Results' : 'Fixtures'}</h2><div className="fixture-toolbar"><button onClick={() => show('Competition')}>Competition</button></div><div className="fixture-list">{phases.map(phase => <div key={phase} className="fixture-phase"><h3>{phase}</h3>{games.filter(item => item.phase===phase).map(item => <FixtureRow key={item.id} fixture={item} clubClick={clubClick} />)}</div>)}</div></section>;
}
function FixtureRow({fixture,clubClick}:{fixture:Fixture;clubClick:(id:string)=>void}) {
  return <div className="fixture-row"><span className="place">{fixture.homeScore === undefined?'2nd':'1st'}</span><button className="fixture-club" onClick={() => clubClick(fixture.homeClubId)}>{clubName(fixture.homeClubId)}</button><span className="fixture-score">{fixture.homeScore === undefined?'v':`${fixture.homeScore} : ${fixture.awayScore}`}</span><button className="fixture-club" onClick={() => clubClick(fixture.awayClubId)}>{clubName(fixture.awayClubId)}</button><span className="place">{fixture.awayScore === undefined?'3rd':'4th'}</span></div>;
}

const clubTabs = ['Squad','Transfers','Next Match','Fixtures','Finances & Info'];
function ClubScreen({club,players,openPlayer,show}:{club:Club;players:Player[];openPlayer:(id:string)=>void;show:(label:string)=>void}) {
  return <section className="club-screen"><nav className="tabs" aria-label="Club tabs">{clubTabs.map((tab,index)=><button key={tab} className={index===0?'active':''} onClick={() => index!==0 && show(tab)}>{tab}</button>)}</nav><div className="subtools"><button onClick={() => show('Squad View')}>View ▾</button><h2>Selection Info</h2><button onClick={() => show('Clear Squad')}>Clear Squad</button><button onClick={() => show('Filter')}>Filter ▾</button></div><div className="roster-scroller"><table className="roster"><thead><tr>{['Pkd','Inf','Name','Position','Form','Morale','Cond.','Apps','Av R','Value'].map(label=><th key={label}>{label}</th>)}</tr></thead><tbody>{players.map(player=><tr key={player.id}><td className="picked"></td><td></td><td className="name"><button onClick={() => openPlayer(player.id)}>{player.name}</button></td><td className="cyan">{player.position}</td><td>{player.form}</td><td>{player.morale}</td><td className="orange">{player.condition}</td><td className="cyan">{player.appearances}</td><td className="cyan">{player.averageRating}</td><td className="value">{player.value}</td></tr>)}</tbody></table></div><div className="bottom-strip">{['Tactics','Training','Last Match',club.division,'History'].map(label=><button key={label} onClick={() => show(label)}>{label} ▸</button>)}</div></section>;
}

const profileTabs = ['Profile','Injuries & Bans','Contract','Transfer','History'];
function PlayerScreen({player,show}:{player:Player;show:(label:string)=>void}) {
  const columns=[player.attributes.slice(0,12),player.attributes.slice(12,24),player.attributes.slice(24,31)];
  return <section className="player-screen"><nav className="tabs" aria-label="Player tabs">{profileTabs.map((tab,index)=><button key={tab} className={index===0?'active':''} onClick={() => index!==0 && show(tab)}>{tab}</button>)}</nav><h2 className="player-bio">Born {player.born} (Age {player.age}). {player.nationality}.</h2><div className="attributes">{columns.map((column,index)=><div key={index}>{column.map(([label,value])=><div className="attribute" key={label}><span>{label}</span><strong>{value}</strong></div>)}{index===2&&[['Preferred Foot',player.preferredFoot],['Form',player.form],['Morale',player.morale],['Condition',player.condition]].map(([label,value])=><div className="attribute" key={label}><span>{label}</span><strong className="orange">{value}</strong></div>)}</div>)}</div><div className="player-stats"><div className="stat-head"><span></span>{['Apps','Con','Asts','MoM','Pass','Tck','Drb','Av R'].map(v=><span key={v}>{v}</span>)}</div>{['Non Competitive','League','Cup','Continental','International','Senior Club'].map((row,i)=><div className="stat-row" key={row}><span>{row}</span><span>{i*3+2}</span><span>{i+1}</span><span>{i===1?2:0}</span><span>0</span><span>{i?`${50+i}%`:'-'}</span><span>{i?`${(i/3).toFixed(1)}`:'-'}</span><span>0.0</span><span className="rating">{i?`${(6.4+i/10).toFixed(2)}`:'-----'}</span></div>)}</div><div className="player-role">{player.position.startsWith('GK')?'Goalkeeper':'Footballer'}</div></section>;
}

createRoot(document.getElementById('root')!).render(<App />);
