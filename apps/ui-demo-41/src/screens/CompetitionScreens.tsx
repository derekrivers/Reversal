import { useState } from 'react';
import { demoData } from '../data';
import type { Fixture } from '../types';
import './CompetitionScreens.css';

export type CompetitionKind = 'cup' | 'league';
export type CompetitionMode = 'stages' | 'table' | 'results' | 'fixtures' | 'schedule';

interface CompetitionScreensProps {
  kind: CompetitionKind;
  mode: CompetitionMode;
  selectedGroup: string;
  onMode: (mode: CompetitionMode) => void;
  onGroup: (groupId: string) => void;
  onClub: (clubId: string) => void;
  show: (label: string) => void;
}

interface Standing {
  clubId: string;
  played: number;
  won: number;
  drawn: number;
  lost: number;
  goalsFor: number;
  goalsAgainst: number;
  points: number;
}

const allFixtures = [...demoData.fixtures].sort((a, b) => a.date.localeCompare(b.date) || a.id.localeCompare(b.id));
const complete = (fixture: Fixture): boolean => fixture.homeScore !== undefined && fixture.awayScore !== undefined;
const club = (id: string) => demoData.clubs[id];

function standings(clubIds: readonly string[], fixtures: readonly Fixture[]): Standing[] {
  const rows = new Map<string, Standing>(clubIds.map(clubId => [clubId, {
    clubId, played: 0, won: 0, drawn: 0, lost: 0, goalsFor: 0, goalsAgainst: 0, points: 0,
  }] as const));
  fixtures.filter(complete).forEach(fixture => {
    const home = rows.get(fixture.homeClubId);
    const away = rows.get(fixture.awayClubId);
    if (!home || !away) return;
    const homeScore = fixture.homeScore!;
    const awayScore = fixture.awayScore!;
    home.played++; away.played++;
    home.goalsFor += homeScore; home.goalsAgainst += awayScore;
    away.goalsFor += awayScore; away.goalsAgainst += homeScore;
    if (homeScore > awayScore) { home.won++; home.points += 3; away.lost++; }
    else if (awayScore > homeScore) { away.won++; away.points += 3; home.lost++; }
    else { home.drawn++; away.drawn++; home.points++; away.points++; }
  });
  return [...rows.values()].sort((a, b) => b.points - a.points
    || (b.goalsFor - b.goalsAgainst) - (a.goalsFor - a.goalsAgainst)
    || b.goalsFor - a.goalsFor
    || club(a.clubId).name.localeCompare(club(b.clubId).name));
}

function dateParts(iso: string) {
  const [year, month, day] = iso.split('-').map(Number);
  const date = new Date(Date.UTC(year, month - 1, day));
  const weekday = new Intl.DateTimeFormat('en-GB', { weekday: 'long', timeZone: 'UTC' }).format(date);
  const monthName = new Intl.DateTimeFormat('en-GB', { month: 'long', timeZone: 'UTC' }).format(date);
  const shortWeekday = weekday.slice(0, 3);
  const suffix = day % 10 === 1 && day !== 11 ? 'st' : day % 10 === 2 && day !== 12 ? 'nd' : day % 10 === 3 && day !== 13 ? 'rd' : 'th';
  return { long: `${weekday} ${day}${suffix} ${monthName}`, short: `${shortWeekday} ${day}${suffix} ${monthName} ${year}`, compact: `${day}.${month}.${String(year).slice(-2)}` };
}

function StandingTable({ rows, onClub, cup }: {rows: Standing[]; onClub: (clubId: string) => void; cup: boolean}) {
  return <div className="uicom-standings" role="table" aria-label={cup ? 'Group standings' : 'League table'}>
    <div className="uicom-standing-head" role="row"><span/><span/><span>{cup ? 'Nation' : ''}</span>{['Pld', 'Won', 'Drn', 'Lst', 'For', 'Ag', 'Pts'].map(label => <span key={label}>{label}</span>)}</div>
    {rows.map((row, index) => <div className={`uicom-standing-row ${cup && index === 2 ? 'uicom-cutoff' : ''}`} role="row" key={row.clubId}>
      <span className="uicom-rank">{index + 1}{index === 0 ? 'st' : index === 1 ? 'nd' : index === 2 ? 'rd' : 'th'}</span>
      <button onClick={() => onClub(row.clubId)}>{club(row.clubId).shortName}</button>
      <span className="uicom-nation">{cup ? club(row.clubId).nation.slice(0, 3).toUpperCase() : ''}</span>
      {[row.played, row.won, row.drawn, row.lost, row.goalsFor, row.goalsAgainst].map((value, cell) => <span key={cell}>{value}</span>)}
      <span className="uicom-points">{row.points}</span>
    </div>)}
  </div>;
}

function ClubLink({id, onClub}: {id: string; onClub: (clubId: string) => void}) {
  return <button className="uicom-club-link" onClick={() => onClub(id)}>{club(id).shortName}</button>;
}

function StageMatches({fixtures, onClub}: {fixtures: readonly Fixture[]; onClub: (clubId: string) => void}) {
  return <div className="uicom-stage-matches">
    {fixtures.map(fixture => <div className="uicom-stage-match" key={fixture.id}>
      <span className="uicom-date-cell">{dateParts(fixture.date).compact}</span>
      <ClubLink id={fixture.homeClubId} onClub={onClub}/>
      <span className="uicom-stage-score">{complete(fixture) ? `${fixture.homeScore}:${fixture.awayScore}` : 'v'}</span>
      <ClubLink id={fixture.awayClubId} onClub={onClub}/>
      <span className="uicom-venue">{club(fixture.homeClubId).shortName}</span>
      <span className="uicom-extra">----</span>
    </div>)}
  </div>;
}

function MatchDay({fixtures, kind, mode, onClub}: {fixtures: readonly Fixture[]; kind: CompetitionKind; mode: 'results' | 'fixtures'; onClub: (clubId: string) => void}) {
  const date = fixtures[0]?.date;
  const groups = kind === 'cup' ? demoData.competition.groups : [{id: 'division', name: '', clubIds: []}];
  const allPositions = new Map<string, number>();
  groups.forEach(group => standings(group.clubIds.length ? group.clubIds : Object.values(demoData.clubs).filter(item => item.division === demoData.clubs[demoData.managedClubId].division).map(item => item.id), allFixtures).forEach((row, index) => allPositions.set(row.clubId, index + 1)));
  const rank = (id: string) => { const n = allPositions.get(id); return n ? `${n}${n === 1 ? 'st' : n === 2 ? 'nd' : n === 3 ? 'rd' : 'th'}` : '—'; };
  return <div className="uicom-day">
    <h2>{date ? dateParts(date).long : mode === 'results' ? 'Results' : 'Fixtures'}</h2>
    <div className="uicom-day-scroll">{groups.map(group => {
      const matches = fixtures.filter(fixture => kind === 'league' || fixture.phase === group.name);
      if (!matches.length) return null;
      return <section className="uicom-match-group" key={group.id}>
        {kind === 'cup' && <h3>{group.name}</h3>}
        {matches.map(fixture => <div className="uicom-match-row" key={fixture.id}>
          <span className="uicom-rank">{rank(fixture.homeClubId)}</span>
          <ClubLink id={fixture.homeClubId} onClub={onClub}/>
          <span className="uicom-match-score">{mode === 'results' ? `${fixture.homeScore}:${fixture.awayScore}` : 'v'}</span>
          <ClubLink id={fixture.awayClubId} onClub={onClub}/>
          <span className="uicom-rank">{rank(fixture.awayClubId)}</span>
        </div>)}
      </section>;
    })}</div>
  </div>;
}

function Schedule({fixtures, kind}: {fixtures: readonly Fixture[]; kind: CompetitionKind}) {
  const dates = [...new Set(fixtures.map(fixture => fixture.date))];
  return <div className="uicom-schedule" role="table" aria-label="Competition schedule">{dates.map((date, index) => <div className="uicom-schedule-row" role="row" key={date}>
    <span className="uicom-date-cell">{dateParts(date).short}</span>
    <span>{kind === 'cup' ? `Group Stage · Round ${index + 1}` : `Game ${index + 1}`}</span>
  </div>)}</div>;
}

export function CompetitionScreens({kind, mode, selectedGroup, onMode, onGroup, onClub, show}: CompetitionScreensProps) {
  const [groupMenuOpen, setGroupMenuOpen] = useState(false);
  const group = demoData.competition.groups.find(item => item.id === selectedGroup) ?? demoData.competition.groups[0];
  const leagueClubIds = Object.values(demoData.clubs).filter(item => item.division === demoData.clubs[demoData.managedClubId].division).map(item => item.id);
  const leagueFixtures = allFixtures.filter(item => leagueClubIds.includes(item.homeClubId) && leagueClubIds.includes(item.awayClubId));
  const sourceFixtures = kind === 'cup' ? allFixtures : leagueFixtures;
  const activeMode = kind === 'cup' && mode === 'table' ? 'stages' : kind === 'league' && mode === 'stages' ? 'table' : mode;
  const modes: CompetitionMode[] = kind === 'cup' ? ['stages', 'results', 'fixtures', 'schedule'] : ['table', 'results', 'fixtures', 'schedule'];
  const filteredFixtures = sourceFixtures.filter(item => activeMode === 'results' ? complete(item) : !complete(item));
  const selectedDate = activeMode === 'results' ? filteredFixtures.at(-1)?.date : filteredFixtures[0]?.date;
  const dayFixtures = filteredFixtures.filter(item => item.date === selectedDate);
  const isTable = activeMode === 'stages' || activeMode === 'table';
  return <section className={`uicom-screen uicom-${kind}`} aria-label={kind === 'cup' ? demoData.competition.name : demoData.clubs[demoData.managedClubId].division}>
    <nav className="uicom-tabs" aria-label={kind === 'cup' ? 'Cup views' : 'League views'}>{modes.map(item => <button key={item} className={activeMode === item ? 'uicom-active' : ''} aria-current={activeMode === item ? 'page' : undefined} onClick={() => { setGroupMenuOpen(false); onMode(item); }}>{item[0].toUpperCase() + item.slice(1)}</button>)}</nav>
    {isTable ? <>
      <div className="uicom-toolbar">
        <button className="uicom-tool" onClick={() => show('View')}>View <span>▾</span></button>
        {kind === 'cup' && <div className="uicom-right-tools">
          <div className="uicom-group-wrap"><button className="uicom-tool" aria-expanded={groupMenuOpen} aria-haspopup="menu" onClick={() => setGroupMenuOpen(open => !open)}>Group <span>▾</span></button>
            {groupMenuOpen && <div className="uicom-group-menu" role="menu" aria-label="Select group">{demoData.competition.groups.map(item => <button key={item.id} role="menuitemradio" aria-checked={item.id === group.id} onClick={() => { onGroup(item.id); setGroupMenuOpen(false); }}>{item.name}</button>)}</div>}
          </div>
          <button className="uicom-tool" onClick={() => show('Stage')}>Stage <span>▾</span></button>
        </div>}
      </div>
      <h2 className="uicom-heading">{kind === 'cup' ? group.name : 'League Table'}</h2>
      <div className="uicom-table-body"><StandingTable rows={standings(kind === 'cup' ? group.clubIds : leagueClubIds, sourceFixtures)} onClub={onClub} cup={kind === 'cup'}/>
        {kind === 'cup' && <StageMatches fixtures={sourceFixtures.filter(item => item.phase === group.name)} onClub={onClub}/>}
      </div>
    </> : activeMode === 'schedule' ? <Schedule fixtures={sourceFixtures} kind={kind}/> : <>
      <div className="uicom-toolbar uicom-date-tools"><button className="uicom-tool" onClick={() => show('Previous date')}>&lt;&lt; Date</button><button className="uicom-tool" onClick={() => show('Next date')}>Date &gt;&gt;</button></div>
      <MatchDay fixtures={dayFixtures} kind={kind} mode={activeMode as 'results' | 'fixtures'} onClub={onClub}/>
    </>}
    <div className="uicom-bottom-strip">{(kind === 'cup' ? ['Seedings', 'Team Stats', 'Player Stats', 'History'] : ['Team Stats', 'Player Stats', 'Referee Stats', 'Awards', 'History']).map(label => <button key={label} onClick={() => show(label)}>{label}{label === 'History' || label === 'Awards' ? '  ▸' : ''}</button>)}</div>
  </section>;
}
