import { useEffect, useState } from 'react';
import { demoData } from '../data';
import type { Club, Player } from '../types';
import './GlobalScreens.css';

export type GlobalMode =
  | 'find' | 'news' | 'manager-stats' | 'job-info' | 'manager-transfers'
  | 'manager-history' | 'board-confidence' | 'manager-status'
  | 'selected-leagues' | 'game-settings' | 'search';

interface GlobalScreensProps {
  mode: GlobalMode;
  tab: string;
  page: number;
  onTab: (tab: string) => void;
  onPage: (page: number) => void;
  onPlayer: (id: string) => void;
  onClub: (id: string) => void;
  onClose: () => void;
  show: (label: string) => void;
}

const clubs = Object.values(demoData.clubs);
const players = Object.values(demoData.players);
const managedClub = demoData.clubs[demoData.managedClubId];
const findTabs = ['Nation', 'Club', 'Non-Player', 'Player'];
const newsTabs = ['All', 'Messages', 'Competitions', 'Injuries and Bans'];
const searchTabs = ['Short List', 'Player Search', 'Staff Search', 'Scout #1', 'Scout #2'];

function activeTab(tab: string, choices: readonly string[], fallback: string): string {
  return choices.find(choice => choice.toLowerCase() === tab.toLowerCase()) ?? fallback;
}

function Tabs({ labels, selected, onTab, name }: { labels: readonly string[]; selected: string; onTab: (tab: string) => void; name: string }) {
  return <nav className="gsc-tabs" aria-label={name}>{labels.map(label => <button type="button" key={label} className={selected === label ? 'gsc-active' : ''} onClick={() => onTab(label)}>{label}</button>)}</nav>;
}

function Pager({ page, total, onPage }: { page: number; total: number; onPage: (page: number) => void }) {
  const current = Math.min(Math.max(1, page || 1), Math.max(1, total));
  return <div className="gsc-pager" aria-label="Result pages">
    <button type="button" aria-label="First page" disabled={current === 1} onClick={() => onPage(1)}>◀◀</button>
    <button type="button" aria-label="Previous page" disabled={current === 1} onClick={() => onPage(current - 1)}>◀</button>
    <span>Pg {current}/{Math.max(1, total)}</span>
    <button type="button" aria-label="Next page" disabled={current >= total} onClick={() => onPage(current + 1)}>▶</button>
    <button type="button" aria-label="Last page" disabled={current >= total} onClick={() => onPage(total)}>▶▶</button>
  </div>;
}

type FindRow = { id: string; name: string; middle: string; last: string; kind: 'player' | 'club' | 'nation' | 'staff' };

function findRows(tab: string): FindRow[] {
  if (tab === 'Player') return players.map(player => ({ id: player.id, name: player.name, middle: demoData.clubs[player.clubId]?.shortName ?? '', last: demoData.clubs[player.clubId]?.division ?? '', kind: 'player' }));
  if (tab === 'Club') return clubs.map(club => ({ id: club.id, name: club.name, middle: club.nation, last: club.division, kind: 'club' }));
  if (tab === 'Nation') return [
    { id: 'england', name: 'England', middle: 'Europe', last: 'UEFA', kind: 'nation' },
    { id: 'ireland', name: 'Ireland', middle: 'Europe', last: 'UEFA', kind: 'nation' },
    { id: 'scotland', name: 'Scotland', middle: 'Europe', last: 'UEFA', kind: 'nation' },
    { id: 'wales', name: 'Wales', middle: 'Europe', last: 'UEFA', kind: 'nation' },
  ];
  return clubs.map(club => ({ id: club.id, name: club.manager, middle: club.shortName, last: club.division, kind: 'staff' }));
}

function FindScreen({ tab, page, onTab, onPage, onPlayer, onClub, show }: GlobalScreensProps) {
  const selected = activeTab(tab, findTabs, 'Player');
  const [query, setQuery] = useState('');
  const rows = findRows(selected).filter(row => row.name.toLowerCase().includes(query.trim().toLowerCase()));
  const perPage = 16;
  const total = Math.max(1, Math.ceil(rows.length / perPage));
  const current = Math.min(Math.max(1, page || 1), total);
  const visible = rows.slice((current - 1) * perPage, current * perPage);
  function selectTab(next: string) { setQuery(''); onTab(next); }
  function openRow(row: FindRow) {
    if (row.kind === 'player') onPlayer(row.id);
    else if (row.kind === 'club') onClub(row.id);
    else show(row.kind === 'nation' ? 'Nation details' : 'Non-Player profile');
  }
  return <section className="gsc-screen gsc-find">
    <Tabs labels={findTabs} selected={selected} onTab={selectTab} name="Find categories" />
    <div className="gsc-find-tools"><label>Search For <input value={query} onChange={event => { setQuery(event.target.value); onPage(1); }} aria-label="Search fictional results" /></label><Pager page={current} total={total} onPage={onPage} /></div>
    <h2 className="gsc-section-title">All {selected === 'Non-Player' ? 'Non-Players' : `${selected}s`}</h2>
    <div className="gsc-find-list" aria-label={`${selected} results`}>{visible.map(row => <button type="button" className="gsc-find-row" key={`${row.kind}-${row.id}`} onClick={() => openRow(row)}><strong>{row.name}</strong><span>{row.middle}</span><em>{row.last}</em></button>)}
      {visible.length === 0 && <div className="gsc-empty">No fictional results match this search.</div>}
    </div>
  </section>;
}

type NewsStory = { id: string; date: string; title: string; text: string; category: string };
const newsStories: NewsStory[] = [
  { id: 'training', date: 'Wed 16th Jul EVE', title: 'Training report from the coaching staff', text: `The coaching staff report that ${players[0].name} has worked well this week at ${managedClub.shortName}.`, category: 'Messages' },
  { id: 'cup', date: 'Tue 15th Jul PM', title: `${demoData.competition.name} fixtures announced`, text: `${managedClub.shortName} will meet ${clubs[1].shortName} in the next group fixture.`, category: 'Competitions' },
  { id: 'board', date: 'Mon 14th Jul PM', title: 'Board reaction to the latest match', text: `The ${managedClub.shortName} board is pleased with the team's recent result.`, category: 'Messages' },
  { id: 'fitness', date: 'Sat 12th Jul PM', title: 'Fitness update', text: 'The medical team has no new injuries to report in this fictional season.', category: 'Injuries and Bans' },
  { id: 'transfer', date: 'Fri 11th Jul PM', title: 'Transfer news around the league', text: `${clubs[2].shortName} have completed a fictional squad move.`, category: 'All' },
];

function NewsScreen({ tab, onTab, show }: GlobalScreensProps) {
  const selected = activeTab(tab, newsTabs, 'All');
  const stories = selected === 'All' ? newsStories : newsStories.filter(story => story.category === selected);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const story = stories.find(item => item.id === selectedId) ?? stories[0];
  useEffect(() => setSelectedId(null), [selected]);
  return <section className="gsc-screen gsc-news">
    <Tabs labels={newsTabs} selected={selected} onTab={onTab} name="News categories" />
    <div className="gsc-news-list">{stories.map(item => <button type="button" key={item.id} className={story?.id === item.id ? 'gsc-selected' : ''} onClick={() => setSelectedId(item.id)}><span>{item.date}</span><strong>{item.title}</strong></button>)}</div>
    <div className="gsc-news-tools"><button type="button" onClick={() => show('News Filter')}>Filter ▾</button><button type="button" onClick={() => show('Next Unread')}>Next Unread</button></div>
    {story && <article className="gsc-news-detail"><h2>{story.title}</h2><p>{story.text}</p></article>}
    <div className="gsc-news-bottom">{['Contracts and Media', 'Transfers', 'Jobs', 'Records'].map(label => <button type="button" key={label} onClick={() => show(`News ${label}`)}>{label}</button>)}</div>
  </section>;
}

function ManagerStats({ tab, page, onTab, onPage, onClub, show }: GlobalScreensProps) {
  const nation = tab && tab !== 'All' ? tab : 'England';
  const rows = [managedClub, ...clubs.filter(club => club.id !== managedClub.id)].filter(club => club.nation === nation);
  const current = Math.min(Math.max(1, page || 1), Math.max(1, Math.ceil(rows.length / 4)));
  return <section className="gsc-screen gsc-manager-list">
    <h2 className="gsc-section-title">Reputation in {nation}</h2>
    <div className="gsc-list-tools"><button type="button" onClick={() => onTab(nation === 'England' ? 'Scotland' : 'England')}>Nation ▾</button><Pager page={current} total={Math.ceil(rows.length / 4)} onPage={onPage} /></div>
    <div className="gsc-manager-rows">{rows.slice((current - 1) * 4, current * 4).map((club, offset) => { const rank = (current - 1) * 4 + offset + 1; return <button type="button" className="gsc-manager-row" key={club.id} onClick={() => rank === 1 ? show('Manager profile') : onClub(club.id)}><span>{rank}{rank === 1 ? 'st' : rank === 2 ? 'nd' : rank === 3 ? 'rd' : 'th'}</span><strong>{club.manager}</strong><b>{club.shortName}</b><em>{rank < 3 ? 'Very Good' : 'Good'}</em></button>; })}{rows.length === 0 && <div className="gsc-empty">No fictional manager rankings for {nation}.</div>}</div>
  </section>;
}

function JobInfo({ tab, onTab, onClub, show }: GlobalScreensProps) {
  const nation = tab && tab !== 'All' ? tab : 'England';
  const jobs = clubs.filter(club => club.nation === nation).slice(3, 7);
  return <section className="gsc-screen gsc-manager-list"><h2 className="gsc-section-title">{nation}</h2>
    <div className="gsc-list-tools"><button type="button" onClick={() => onTab(nation === 'England' ? 'Scotland' : 'England')}>View ▾</button></div>
    <div className="gsc-manager-rows">{jobs.map((club, index) => <div className="gsc-manager-row gsc-job-row" key={club.id}><strong>{index === 0 ? 'No Manager' : club.manager}</strong><button type="button" onClick={() => onClub(club.id)}>{club.shortName}</button><b>{club.nation}</b><span>{club.division}</span><em>{index === 0 ? 'Available' : 'Secure'}</em></div>)}{jobs.length === 0 && <div className="gsc-empty">No fictional vacancies for {nation}.</div>}</div>
    <button type="button" className="gsc-text-action" onClick={() => show('Job Application')}>View job details</button>
  </section>;
}

function ManagerTransfers({ tab, page, onTab, onPage, onPlayer, onClub, show }: GlobalScreensProps) {
  const selected = tab && tab !== 'All' ? tab : 'All Transfers';
  const items = players.slice(0, 20).map((player, index) => ({ player, from: demoData.clubs[player.clubId], to: clubs[(index + 2) % clubs.length], day: 15 - index % 12 }));
  const visible = items.slice((Math.max(1, page || 1) - 1) * 12, Math.max(1, page || 1) * 12);
  return <section className="gsc-screen gsc-manager-list"><h2 className="gsc-section-title">July 2003 <button type="button" onClick={() => show('Transfer month')}>◀ ▶</button></h2>
    <div className="gsc-list-tools"><button type="button" onClick={() => onTab(selected === 'All Transfers' ? 'England' : 'All Transfers')}>View ▾ {selected}</button><Pager page={page} total={2} onPage={onPage} /></div>
    <div className="gsc-transfer-list">{visible.map(({ player, from, to, day }) => <div className="gsc-transfer-row" key={player.id}><span>{day}th Jul</span><button type="button" onClick={() => onPlayer(player.id)}>{player.name}</button><button type="button" onClick={() => onClub(from.id)}>{from.shortName}</button><span>to</span><button type="button" onClick={() => onClub(to.id)}>{to.shortName}</button><em>{player.value}</em></div>)}</div>
  </section>;
}

function ManagerHistory({ tab, onTab, show }: GlobalScreensProps) {
  const view = tab && tab !== 'History' ? tab : 'Achievements';
  const events = [
    ['16.7.03', managedClub.shortName, `Qualified for the ${demoData.competition.name} group stage`],
    ['12.7.03', managedClub.shortName, 'Opened the new fictional season'],
    ['30.6.03', managedClub.shortName, 'Supporters welcomed the new campaign'],
    ['18.5.03', managedClub.shortName, 'County Shield semi-finalists'],
  ];
  return <section className="gsc-screen gsc-manager-history">
    <Tabs labels={['Injuries & Bans', 'Contract', 'Transfer', 'History']} selected="History" onTab={label => label === 'History' ? onTab('Achievements') : show(`Manager ${label}`)} name="Manager tabs" />
    <div className="gsc-list-tools"><button type="button" onClick={() => onTab(view === 'Achievements' ? 'Playing Career' : 'Achievements')}>View ▾ {view}</button><button type="button" onClick={() => show('Manager History Filter')}>Filter ▾</button></div>
    <h2 className="gsc-section-title">{view}</h2>
    <div className="gsc-history-events">{view === 'Achievements' ? events.map(([date, club, text]) => <div key={date}><span>{date}</span><span>{club}</span><strong>{text}</strong></div>) : <><div><span>2002/3</span><span>{managedClub.shortName}</span><strong>Second Division</strong></div><div><span>2001/2</span><span>{managedClub.shortName}</span><strong>County Shield semi-finalists</strong></div></>}</div>
    <div className="gsc-role">Manager</div>
  </section>;
}

function BoardConfidence({ show }: GlobalScreensProps) {
  return <section className="gsc-screen gsc-board"><h2 className="gsc-section-title">Board Confidence</h2>
    <div className="gsc-list-tools"><button type="button" onClick={() => show('Board Request')}>Board Request</button><button type="button" onClick={() => show('FA Request')}>FA Request</button></div>
    <p>The {managedClub.name} directors are pleased with your general performance as manager.</p><p>The club’s financial status is stable.</p>
  </section>;
}

function ManagerStatus({ onClub }: GlobalScreensProps) {
  return <section className="gsc-screen gsc-options"><h2 className="gsc-section-title">Manager Status</h2><div className="gsc-status-row"><strong>{managedClub.manager}</strong><button type="button" onClick={() => onClub(managedClub.id)}>{managedClub.shortName}</button><span>Playing</span></div></section>;
}

function SelectedLeagues({ show }: GlobalScreensProps) {
  const nations = ['England', 'France', 'Germany', 'Italy', 'Scotland', 'Wales', 'Ireland'];
  return <section className="gsc-screen gsc-options"><h2 className="gsc-section-title">Selected League(s)</h2>
    <div className="gsc-league-tools"><span>Use Real Players: <b>Yes</b></span><span>Attribute Masking: <b>Yes</b></span><button type="button" onClick={() => show('Select All Leagues')}>Select All</button><button type="button" onClick={() => show('De-select All Leagues')}>De-select All</button></div>
    <div className="gsc-league-list">{nations.map((nation, index) => <div key={nation}><strong>{nation}</strong><span>{index < 4 ? 'SELECTED' : 'BACKGROUND'}</span><span>{index === 0 ? 'Conference Division' : index === 1 ? 'National Division' : ''}</span></div>)}</div>
  </section>;
}

function GameSettings({ onClose, show }: GlobalScreensProps) {
  const settings = [
    ['Language', 'English'], ['Currency', '£'], ['Fonts', 'Default'], ['Wages', 'Weekly'],
    ['Screen Mode', 'Windowed'], ['Background Changes', 'On'], ['Sound', 'Off'],
    ['Database', 'Medium'], ['Matches Stored', '10000'], ['Auto Save', 'Never'],
    ['Save Compressed', 'Yes'], ['Save Safely', 'Yes'], ['Flashing Text', 'Off'],
    ['Background Matches', 'Normal'], ['Print To', 'File'],
  ];
  return <section className="gsc-screen gsc-settings-shell"><div className="gsc-settings-dialog" role="dialog" aria-modal="true" aria-label="Game Settings">
    <h2>Game Settings</h2><div className="gsc-settings-version">Fictional demonstration settings <button type="button" onClick={() => show('Reset Game Settings')}>Reset</button></div>
    <div className="gsc-settings-list">{settings.map(([label, value]) => <button type="button" key={label} onClick={() => show(`Game Settings ${label}`)}><strong>{label}</strong><span>{value}</span></button>)}</div>
    <div className="gsc-dialog-actions"><button type="button" onClick={onClose}>Cancel</button><button type="button" onClick={() => show('Apply Game Settings')}>Ok</button></div>
  </div></section>;
}

function SearchScreen({ tab, page, onTab, onPage, onPlayer, onClose, show }: GlobalScreensProps) {
  const selected = activeTab(tab, searchTabs, 'Player Search');
  const roster = players.filter(player => player.clubId === managedClub.id);
  const staff = selected === 'Staff Search';
  const resultCount = staff ? clubs.length : selected === 'Short List' ? 4 : roster.length;
  const current = Math.min(Math.max(1, page || 1), Math.max(1, Math.ceil(resultCount / 8)));
  const visiblePlayers = (selected === 'Short List' ? roster.slice(0, 4) : roster).slice((current - 1) * 8, current * 8);
  const visibleStaff = clubs.slice((current - 1) * 8, current * 8);
  return <section className="gsc-screen gsc-search-shell"><Tabs labels={searchTabs} selected={selected} onTab={onTab} name="Player and staff search tabs" />
    <div className="gsc-search-tools">{['Search', 'View', 'Filters', 'Delete'].map(label => <button type="button" key={label} onClick={() => show(`${label} Search`)}>{label} ▾</button>)}</div>
    <div className="gsc-search-subtitle">Fictional {staff ? 'staff' : 'players'} in your region <Pager page={current} total={Math.ceil(resultCount / 8)} onPage={onPage} /></div>
    <h2 className="gsc-section-title">{selected}</h2>
    <div className="gsc-search-results"><div className="gsc-search-head"><span>Inf</span><span>Name</span><span>Club</span><span>Based</span><span>Position</span><span>Value</span></div>
      {staff ? visibleStaff.map(club => <button type="button" className="gsc-search-row" key={club.id} onClick={() => show('Staff profile')}><span></span><strong>{club.manager}</strong><span>{club.shortName}</span><span>{club.nation}</span><span>Manager</span><em>-</em></button>)
        : visiblePlayers.map((player: Player) => <button type="button" className="gsc-search-row" key={player.id} onClick={() => onPlayer(player.id)}><span></span><strong>{player.name}</strong><span>{managedClub.shortName}</span><span>{managedClub.nation}</span><span>{player.position}</span><em>{player.value}</em></button>)}
    </div>
    <p className="gsc-search-count">{resultCount} fictional {staff ? 'staff' : 'players'} found</p>
    <div className="gsc-search-scouts">{['Scout #3', 'Scout #4', 'Scout #5', 'Scout #6', 'Scout #7'].map(label => <button type="button" key={label} onClick={() => show(label)}>{label}</button>)}</div>
    <div className="gsc-dialog-actions"><button type="button" onClick={onClose}>Cancel</button><button type="button" onClick={() => show('Confirm Search')}>Ok</button></div>
  </section>;
}

export function GlobalScreens(props: GlobalScreensProps) {
  switch (props.mode) {
    case 'find': return <FindScreen {...props} />;
    case 'news': return <NewsScreen {...props} />;
    case 'manager-stats': return <ManagerStats {...props} />;
    case 'job-info': return <JobInfo {...props} />;
    case 'manager-transfers': return <ManagerTransfers {...props} />;
    case 'manager-history': return <ManagerHistory {...props} />;
    case 'board-confidence': return <BoardConfidence {...props} />;
    case 'manager-status': return <ManagerStatus {...props} />;
    case 'selected-leagues': return <SelectedLeagues {...props} />;
    case 'game-settings': return <GameSettings {...props} />;
    case 'search': return <SearchScreen {...props} />;
  }
}
