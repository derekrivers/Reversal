export interface Club {
  id: string;
  name: string;
  shortName: string;
  nation: string;
  division: string;
  stadium: string;
  manager: string;
  balance: string;
  transferBudget: string;
}

export interface Player {
  id: string;
  clubId: string;
  name: string;
  position: string;
  squadNumber: number;
  nationality: string;
  age: number;
  born: string;
  bio: string;
  attributes: ReadonlyArray<readonly [label: string, value: number]>;
  preferredFoot: string;
  form: string;
  morale: string;
  condition: string;
  appearances: string;
  averageRating: string;
  value: string;
}

export interface Fixture {
  id: string;
  competitionId: string;
  phase: string;
  date: string;
  homeClubId: string;
  awayClubId: string;
  homeScore?: number;
  awayScore?: number;
  venue: string;
}

export interface Competition {
  id: string;
  name: string;
  groups: ReadonlyArray<{ id: string; name: string; clubIds: ReadonlyArray<string> }>;
}

export interface DemoData {
  managedClubId: string;
  clubs: Record<string, Club>;
  players: Record<string, Player>;
  fixtures: ReadonlyArray<Fixture>;
  competition: Competition;
  dateLabel: string;
}
