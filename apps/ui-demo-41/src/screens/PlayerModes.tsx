import { useEffect, useState } from 'react';
import { demoData } from '../data';
import type { Player } from '../types';
import './PlayerModes.css';

export type PlayerDetailMode = 'injuries-bans' | 'contract' | 'transfer' | 'history';
export type PlayerHistoryView = 'Achievements' | 'Playing Career' | 'Injuries' | 'Bans';

interface PlayerModesProps {
  player: Player;
  mode: PlayerDetailMode;
  show: (label: string) => void;
  historyView?: PlayerHistoryView;
  onHistoryView?: (view: PlayerHistoryView) => void;
}

const historyViews: readonly PlayerHistoryView[] = ['Achievements', 'Playing Career', 'Injuries', 'Bans'];
const statColumns = ['Apps', 'Con', 'Asts', 'MoM', 'Pass', 'Tck', 'Drb', 'Sh Tar', 'Av R'];
const statSections = ['Non Competitive', 'League', 'Cup', 'Continental', 'International', 'Senior Club'];

function fictionalClub(player: Player): string {
  return demoData.clubs[player.clubId]?.shortName ?? player.clubId;
}

function numericAppearances(player: Player): number {
  return Number.parseInt(player.appearances, 10) || 0;
}

function DetailRows({ rows }: { rows: ReadonlyArray<readonly [string, string]> }) {
  return <div className="pmd-detail-rows">
    {rows.map(([label, value]) => <div className="pmd-detail-row" key={label}>
      <span className="pmd-detail-label">{label}</span><strong className="pmd-detail-value">{value}</strong>
    </div>)}
  </div>;
}

function SeasonStats({ player, show, caption }: { player: Player; show: (label: string) => void; caption?: string }) {
  const apps = numericAppearances(player);
  const sections = statSections.map((label, index) => {
    const played = index === 0 ? 0 : index === 1 ? apps : index === 5 ? apps + 3 : index === 2 ? 3 : 0;
    return { label, played, conceded: player.position.startsWith('GK') ? Math.max(0, Math.round(played * .8)) : 0 };
  });
  return <div className="pmd-stats" aria-label="Fictional season statistics">
    <div className="pmd-stat-caption">{caption ?? ''}</div>
    <div className="pmd-stat-grid pmd-stat-head">
      <div className="pmd-stat-arrows"><button type="button" aria-label="Previous statistics" onClick={() => show('Previous statistics')}>◀</button><button type="button" aria-label="Next statistics" onClick={() => show('Next statistics')}>▶</button></div>
      {statColumns.map(label => <span key={label}>{label}</span>)}
    </div>
    {sections.map(({ label, played, conceded }) => <div className="pmd-stat-grid pmd-stat-line" key={label}>
      <span className="pmd-stat-category">{label}</span>
      <span>{played || '-'}</span><span>{conceded || '-'}</span><span>0</span><span>0</span>
      <span>{played ? '53%' : '-'}</span><span>{played ? '1.1' : '-'}</span><span>{played ? '0.8' : '-'}</span><span>-</span>
      <span className="pmd-stat-rating">{played ? player.averageRating : '-----'}</span>
    </div>)}
  </div>;
}

function HistoryBody({ player, view, show }: { player: Player; view: PlayerHistoryView; show: (label: string) => void }) {
  const club = fictionalClub(player);
  const apps = numericAppearances(player);
  if (view === 'Playing Career') {
    const seasons = [
      { year: '2002/3', club, played: apps, mark: true },
      { year: '2001/2', club, played: Math.max(8, apps - 5) },
      { year: '2000/1', club: 'Copperdale', played: 29 },
      { year: '1999/00', club: 'Copperdale', played: 24 },
      { year: '1998/99', club: 'Seabourne', played: 19 },
      { year: '1997/98', club: 'Seabourne', played: 12 },
    ];
    return <div className="pmd-history-list pmd-history-career">
      <div className="pmd-history-title">Playing Career</div>
      <div className="pmd-career-heading"><span></span><span></span>{statColumns.map(label => <span key={label}>{label}</span>)}</div>
      <div className="pmd-history-scroll">
        {seasons.map(season => <button type="button" className={`pmd-career-row${season.mark ? ' pmd-selected' : ''}`} key={season.year} onClick={() => show(`Career season ${season.year}`)}>
          <span>{season.year}</span><span>{season.club}</span><span>{season.played}</span><span>{player.position.startsWith('GK') ? Math.round(season.played * .8) : 0}</span><span>0</span><span>0</span><span>53%</span><span>1.1</span><span>0.8</span><span>-</span><span>{player.averageRating}</span>
        </button>)}
      </div>
    </div>;
  }
  if (view === 'Achievements') {
    const rows = [
      ['14.6.03', club, 'North Coast Cup semi-finalists'],
      ['3.5.03', club, 'Supporters’ player of the season'],
      ['18.5.02', 'Copperdale', 'County Shield winners'],
      ['11.8.01', 'Copperdale', 'County Shield runners up'],
      ['7.5.00', 'Seabourne', 'Young player of the season'],
      ['29.4.99', 'Seabourne', 'County Shield finalists'],
    ];
    return <div className="pmd-history-list">
      <div className="pmd-history-title">Achievements</div>
      {rows.map(([date, team, achievement]) => <div className="pmd-achievement-row" key={`${date}-${achievement}`}><span>{date}</span><span>{team}</span><strong>{achievement}</strong></div>)}
    </div>;
  }
  if (view === 'Injuries') {
    const rows = [
      ['23.2.03', 'Sprained ankle', 'Match', '10 days'],
      ['9.10.01', 'Bruised shoulder', 'Training', '1 week'],
      ['18.3.00', 'Twisted knee', 'Match', '2 weeks'],
    ];
    return <div className="pmd-history-list">
      <div className="pmd-history-title">Injuries</div>
      <div className="pmd-injury-heading"><span></span><span></span><span>Type</span><span>Period Out</span></div>
      {rows.map(([date, injury, type, period]) => <div className="pmd-injury-row" key={date}><span>{date}</span><strong>{injury}</strong><span>{type}</span><span>{period}</span></div>)}
    </div>;
  }
  return <div className="pmd-history-list"><div className="pmd-history-title">Bans</div><div className="pmd-empty-rows" aria-label="No fictional ban history entries" /></div>;
}

export function PlayerModes({ player, mode, show, historyView, onHistoryView }: PlayerModesProps) {
  const [localHistoryView, setLocalHistoryView] = useState<PlayerHistoryView>('Playing Career');
  const [viewOpen, setViewOpen] = useState(false);
  const activeHistoryView = historyView ?? localHistoryView;

  useEffect(() => setViewOpen(false), [mode, player.id]);

  function selectHistoryView(view: PlayerHistoryView) {
    if (historyView === undefined) setLocalHistoryView(view);
    onHistoryView?.(view);
    setViewOpen(false);
  }

  const details: Record<Exclude<PlayerDetailMode, 'history'>, ReadonlyArray<readonly [string, string]>> = {
    'injuries-bans': [
      ['Injury', 'None'], ['Type', '-'], ['Condition', player.condition], ['Training', 'Full'], ['Bans', 'No current suspension'],
    ],
    contract: [
      ['Type', 'Full Time Contract'], ['Wages', `£${1_200 + player.squadNumber * 75} per week`],
      ['Started', '1.7.02'], ['Protected', 'Yes'], ['Expires', '30.6.06'],
      ['Squad Status', 'First Team Player'], ['Bonuses', 'Clean Sheet Bonus'],
      ['Clauses', 'None'], ['Work Permit', 'Not required'], ['Notes', ''],
    ],
    transfer: [
      ['Availability', 'Unknown'], ['Value', player.value], ['Fluent Languages', 'English'],
      ['Basic Languages', 'None'], ['Offers', 'None'], ['Interested', 'None'], ['Future', 'Happy to stay at the club'],
    ],
  };

  return <section className="pmd-body" aria-label={`${player.name} ${mode === 'history' ? activeHistoryView : mode} details`}>
    {mode === 'history' ? <>
      <div className="pmd-toolbar">
        <div className="pmd-view-wrap">
          <button type="button" className="pmd-toolbar-button" aria-haspopup="menu" aria-expanded={viewOpen} onClick={() => setViewOpen(open => !open)}>View <span>▾</span></button>
          {viewOpen && <div className="pmd-view-menu" role="menu" aria-label="Player history views">
            {historyViews.map(view => <button type="button" role="menuitemradio" aria-checked={activeHistoryView === view} key={view} onClick={() => selectHistoryView(view)}><span className="pmd-menu-check">{activeHistoryView === view ? '✓' : ''}</span>{view}</button>)}
          </div>}
        </div>
        {activeHistoryView === 'Achievements' && <button type="button" className="pmd-toolbar-button" onClick={() => show('History Filter')}>Filter <span>▾</span></button>}
      </div>
      <HistoryBody player={player} view={activeHistoryView} show={show} />
    </> : <>
      <div className="pmd-bio">Born {player.born} (Age {player.age}). {player.nationality}.</div>
      <DetailRows rows={details[mode]} />
    </>}
    <SeasonStats player={player} show={show} caption={mode === 'history' && activeHistoryView === 'Playing Career' ? `2002/3 ${fictionalClub(player)}` : undefined} />
    <div className="pmd-role">{player.position.startsWith('GK') ? 'Goalkeeper' : 'Footballer'}</div>
  </section>;
}
